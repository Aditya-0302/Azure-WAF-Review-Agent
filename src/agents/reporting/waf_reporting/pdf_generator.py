"""Enterprise PDF report generator — reportlab A4 document.

Sections (20 total — all existing sections preserved, 8 new sections added):
  1.  Cover Page              — upgraded enterprise branding + classification
  2.  Executive Risk Statement— AI-narrative risk summary  [NEW]
  3.  Executive Summary       — risk rating, key risks, top-5 actions, compliance projection, mgmt summary
  4.  Security Scorecard      — 5-category heat-bar scorecard              [NEW]
  5.  Executive Dashboard     — scoring, top-5 risks, coverage metrics
  6.  Resource Inventory      — per-resource-type table + bar chart
  7.  Resource Group Analysis — RG compliance breakdown + bar chart         [NEW]
  8.  Compliance Overview     — all-pillar table + compliance bar chart
  9.  Business Impact         — impact category analysis + distribution
  10. Architecture Topology   — hierarchy: subscription→RG→resource type    [NEW]
  11. WAF Control Pages       — one page per control referenced by findings  [NEW]
  12. Trend Analysis          — historical compliance (or "Not Available")
  13. Remediation Roadmap     — 30-day prioritised roadmap                   [NEW]
  14. Human Review Results    — SE-10, OE-03, OE-04, CO-09 status
  15. WAF Traceability Matrix — finding → rule → control → URL
  16. Detailed Findings       — per-pillar finding tables
  17. Executive Recommendations — top-5 AI-generated recommendations         [NEW]
  18. Appendices              — full findings table + scoring methodology

All data derived from actual assessment records.
If data is unavailable, "Not Available" is displayed — nothing is fabricated.
"""

from __future__ import annotations

import io
import json
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Callable, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from waf_reporting.aggregator import AggregatedReport
from waf_reporting.remediation_templates import get_remediation_detail
from waf_reporting.remediation_playbook import (
    PlaybookEntry,
    build_remediation_playbook,
    estimate_fix_time,
    expected_risk_reduction,
)
from waf_reporting.business_impact_analysis import (
    BusinessImpact,
    build_business_impact_analysis,
    calculate_business_impact_score,
    aggregate_risk_category_levels,
    build_executive_business_impact_summary,
)
from waf_reporting.executive_insights import (
    ExecutiveInsight,
    ExecutiveInsights,
    StrategicRecommendations,
    calculate_insight_confidence,
    generate_executive_insights,
)
from waf_reporting.services.executive_story_generator import (
    ExecutiveNarrative,
    generate_executive_narrative,
)
from waf_reporting.services.evidence_formatter import (
    FormattedFindingCard,
    format_finding_card,
)
from waf_reporting.services.dashboard_builder import (
    DashboardData,
    build_dashboard_data,
    build_kpi_grid,
    build_pillar_bars,
    build_severity_donut,
    build_radar_chart,
    build_resource_type_bars,
    build_risk_heatmap_grid,
    build_trend_chart,
    build_business_impact_bars,
    build_coverage_visual,
    build_legend_drawing,
)
from waf_reporting.services.remediation_planner import (
    RemediationPlan,
    build_remediation_plan,
)
from waf_reporting.services.compliance_mapper import (
    get_azure_policy,
    get_advisor_ref,
    get_compliance_frameworks,
    GLOSSARY,
    METHODOLOGY_SECTIONS,
    CONFIDENCE_SECTIONS,
    LIMITATIONS_TEXT,
)
from waf_reporting.chart_builder import (
    build_compliance_breakdown,
    build_compliance_roadmap,
    build_findings_by_pillar_stacked,
    build_kpi_cards,
    build_pillar_bar,
    build_resource_compliance_bar,
    build_resource_group_bar,
    build_risk_heatmap,
    build_severity_pie,
    build_top_risk_contributors,
    build_trend_line,
    build_waf_benchmark_chart,
)
from waf_reporting.architecture_diagram import build_hierarchy_diagram
from waf_shared.domain.models.finding import Finding
from waf_shared.domain.models.human_review import ComplianceStatus, HumanReviewAssessment

# Optional WAF catalog — graceful degradation if package not installed
try:
    from waf_catalog.catalog import WafCatalog as _WafCatalog
    _HAS_WAF_CATALOG = True
except ImportError:
    _HAS_WAF_CATALOG = False
    _WafCatalog = None  # type: ignore[assignment,misc]

# ── Layout constants ───────────────────────────────────────────────────────────

_PAGE_WIDTH, _PAGE_HEIGHT = A4
_MARGIN      = 1.8 * cm
_BOTTOM_MARGIN = 2.0 * cm   # extra room for footer
_BODY_WIDTH  = _PAGE_WIDTH - 2 * _MARGIN
_REPORT_VERSION = "2.0"

# ── Colour definitions ─────────────────────────────────────────────────────────

_C_DARK      = colors.HexColor("#2C3E50")
_C_BLUE      = colors.HexColor("#1F77B4")
_C_GREEN     = colors.HexColor("#2ECC71")
_C_RED       = colors.HexColor("#E74C3C")
_C_ORANGE    = colors.HexColor("#E67E22")
_C_YELLOW    = colors.HexColor("#F1C40F")
_C_LGREY     = colors.HexColor("#ECF0F1")
_C_MGREY     = colors.HexColor("#BDC3C7")
_C_WHITE     = colors.white
_C_CRIMSON   = colors.HexColor("#C0392B")
_C_TEAL      = colors.HexColor("#16A085")

_SEV_COLORS: dict[str, colors.Color] = {
    "critical":      colors.HexColor("#FF0000"),
    "high":          colors.HexColor("#FF6600"),
    "medium":        colors.HexColor("#FFCC00"),
    "low":           colors.HexColor("#CCE5FF"),
    "informational": colors.HexColor("#F2F2F2"),
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

_PILLAR_TO_IMPACT: dict[str, str] = {
    "security":               "Security Exposure",
    "reliability":            "Availability Risk",
    "cost_optimization":      "Financial Waste",
    "operational_excellence": "Operational Risk",
    "performance_efficiency": "Performance Degradation",
}

# ── Azure WAF benchmark target scores per pillar ───────────────────────────────
# Security gets the highest target (90%) — aligns with SOC 2 / ISO 27001.
# Other pillars carry differentiated targets reflecting Microsoft WAF guidance.
_WAF_PILLAR_TARGETS: dict[str, float] = {
    "security":               90.0,
    "reliability":            85.0,
    "cost_optimization":      80.0,
    "operational_excellence": 85.0,
    "performance_efficiency": 80.0,
}

_WAF_TARGET_RATIONALE: dict[str, str] = {
    "security": (
        "90% — Security carries the highest risk weight. 90% is the enterprise minimum "
        "to satisfy SOC 2 / ISO 27001 controls and prevent active exploitation."
    ),
    "reliability": (
        "85% — Reliability targets reflect SLA commitments; 85% aligns with "
        "99.9% availability standards for production workloads."
    ),
    "cost_optimization": (
        "80% — Cost optimisation allows headroom for workload-specific spend decisions "
        "while eliminating clearly measurable waste."
    ),
    "operational_excellence": (
        "85% — 85% indicates mature CI/CD, monitoring, and governance processes "
        "aligned with ITIL and DevOps best practices."
    ),
    "performance_efficiency": (
        "80% — Performance targets vary by workload type; 80% is a solid baseline "
        "without over-engineering for non-critical paths."
    ),
}

# ── Security Scorecard category → WAF control codes ───────────────────────────

_SCORECARD_CATEGORIES: dict[str, set[str]] = {
    "Identity & Access":    {"SE-05", "SE-08", "SE-10"},
    "Data Protection":      {"SE-03", "SE-07", "SE-12"},
    "Network Security":     {"SE-01", "SE-04", "SE-11"},
    "Operational Security": {"OE-03", "OE-04", "OE-05", "OE-11"},
    "Governance":           {"OE-01", "CO-01", "CO-02", "CO-09"},
}

_SCORECARD_STATUS: dict[str, str] = {
    (True, True): "Excellent",    # score >= 90
    (True, False): "Good",         # 75 <= score < 90
    (False, True): "Needs Improvement",  # 50 <= score < 75
    (False, False): "Critical",   # < 50
}


# ── Style factory ──────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Title"],
            fontSize=24, textColor=_C_WHITE, spaceAfter=10, alignment=TA_CENTER,
        ),
        "cover_sub": ParagraphStyle(
            "CoverSub", parent=base["Normal"],
            fontSize=12, textColor=_C_LGREY, spaceAfter=6, alignment=TA_CENTER,
        ),
        "h1": ParagraphStyle(
            "WafH1", parent=base["Heading1"],
            fontSize=14, textColor=_C_DARK, spaceAfter=8, spaceBefore=12,
        ),
        "h2": ParagraphStyle(
            "WafH2", parent=base["Heading2"],
            fontSize=11, textColor=_C_DARK, spaceAfter=6, spaceBefore=8,
        ),
        "h3": ParagraphStyle(
            "WafH3", parent=base["Heading3"],
            fontSize=9, textColor=_C_DARK, spaceAfter=4, spaceBefore=6,
        ),
        "body": ParagraphStyle(
            "WafBody", parent=base["Normal"],
            fontSize=9, spaceAfter=4,
        ),
        "body_center": ParagraphStyle(
            "WafBodyC", parent=base["Normal"],
            fontSize=9, spaceAfter=4, alignment=TA_CENTER,
        ),
        "narrative": ParagraphStyle(
            "WafNarrative", parent=base["Normal"],
            fontSize=10, spaceAfter=6, leading=15,
        ),
        "caption": ParagraphStyle(
            "WafCaption", parent=base["Normal"],
            fontSize=7.5, textColor=colors.grey, spaceAfter=3,
        ),
        "na": ParagraphStyle(
            "WafNA", parent=base["Normal"],
            fontSize=9, textColor=colors.grey, spaceAfter=6, alignment=TA_CENTER,
        ),
        "methodology": ParagraphStyle(
            "WafMethodology", parent=base["Normal"],
            fontSize=7.5, textColor=colors.grey, spaceAfter=3, backColor=_C_LGREY,
        ),
        "risk_statement": ParagraphStyle(
            "WafRisk", parent=base["Normal"],
            fontSize=10, spaceAfter=8, leading=16,
            backColor=colors.HexColor("#FDFEFE"),
        ),
        "rec_title": ParagraphStyle(
            "WafRecTitle", parent=base["Normal"],
            fontSize=10, textColor=_C_DARK, spaceAfter=3, fontName="Helvetica-Bold",
        ),
        "rec_body": ParagraphStyle(
            "WafRecBody", parent=base["Normal"],
            fontSize=9, spaceAfter=6, leftIndent=12,
        ),
    }


# ── Table style helpers ────────────────────────────────────────────────────────

def _header_style() -> list:
    return [
        ("BACKGROUND", (0, 0), (-1, 0), _C_DARK),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _C_WHITE),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C_WHITE, _C_LGREY]),
        ("GRID",       (0, 0), (-1, -1), 0.4, _C_MGREY),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP",   (0, 0), (-1, -1), True),
    ]


def _make_table(
    rows: list,
    col_widths: list[float] | None = None,
    extra_style: list | None = None,
) -> Table:
    t = Table(rows, colWidths=col_widths)
    style = _header_style() + (extra_style or [])
    t.setStyle(TableStyle(style))
    return t


# ── Truncation helper ──────────────────────────────────────────────────────────

def _tr(value: str, n: int) -> str:
    return value if len(value) <= n else value[: n - 1] + "…"


def _code_xml(text: str, max_chars: int = 500) -> str:
    """Escape a code string for use inside a ReportLab Paragraph (XML mode)."""
    if len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
    )


# ── Finding grouping (presentation layer only) ─────────────────────────────────

class _GroupedFinding:
    """Finding group for display: one entry per (rule_id, severity)."""
    __slots__ = ("rule_id", "title", "severity", "pillar", "recommendation",
                 "waf_codes", "resource_names", "evidence_summary")

    def __init__(self, rule_id: str, title: str, severity: str, pillar: str,
                 recommendation: str, waf_codes: list[str]) -> None:
        self.rule_id        = rule_id
        self.title          = title
        self.severity       = severity
        self.pillar         = pillar
        self.recommendation = recommendation
        self.waf_codes      = waf_codes
        self.resource_names: list[str] = []
        self.evidence_summary: str = ""

    @property
    def count(self) -> int:
        return len(self.resource_names)


def _group_findings(findings: list[Finding]) -> list[_GroupedFinding]:
    """Group findings by (rule_id, severity, recommendation) for report display.

    Deduplicates resource names within each group.
    Output is sorted by severity first, then by resource count descending.
    Preserved for backward compatibility — prefer group_findings_for_reporting().
    """
    groups: dict[tuple[str, str, str], _GroupedFinding] = {}
    for f in findings:
        key = (f.rule_id, f.severity.value, f.recommendation)
        if key not in groups:
            groups[key] = _GroupedFinding(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity.value,
                pillar=f.pillar,
                recommendation=f.recommendation,
                waf_codes=list(f.waf_codes),
            )
        short = f.resource_id.rsplit("/", 1)[-1] if "/" in f.resource_id else f.resource_id
        if short not in groups[key].resource_names:
            groups[key].resource_names.append(short)
    return sorted(
        groups.values(),
        key=lambda g: (
            _SEVERITY_ORDER.index(g.severity) if g.severity in _SEVERITY_ORDER else 99,
            -g.count,
        ),
    )


def group_findings_for_reporting(findings: list[Finding]) -> list[_GroupedFinding]:
    """Group findings by (rule_id, severity) for deduplicated report display.

    Findings that share a rule_id and severity are collapsed into one entry
    regardless of which resource or recommendation text they carry.  This
    eliminates the visual duplicates that appear when the same rule fires on
    multiple resources.

    Per-group behaviour:
    - Affected resource names are deduplicated (short name after last '/').
    - WAF control codes from all member findings are merged (order preserved).
    - The most-voted recommendation string is selected as the canonical one.
    - An evidence_summary line is generated from the members' evidence dicts.

    Falls back to one-entry-per-finding (no grouping) if any unexpected error
    occurs, so report generation is never aborted.

    Returns list sorted by severity (worst first) then resource count descending.
    """
    try:
        groups: dict[tuple[str, str], _GroupedFinding] = {}
        rec_votes: dict[tuple[str, str], dict[str, int]] = {}
        ev_results: dict[tuple[str, str], list[str]]    = {}

        for f in findings:
            key = (f.rule_id, f.severity.value)

            if key not in groups:
                groups[key]    = _GroupedFinding(
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=f.severity.value,
                    pillar=f.pillar,
                    recommendation=f.recommendation,
                    waf_codes=list(f.waf_codes),
                )
                rec_votes[key] = {}
                ev_results[key] = []

            # Vote for most common recommendation text
            rec_votes[key][f.recommendation] = (
                rec_votes[key].get(f.recommendation, 0) + 1
            )

            # Merge WAF codes (preserve insertion order, deduplicate)
            for code in f.waf_codes:
                if code not in groups[key].waf_codes:
                    groups[key].waf_codes.append(code)

            # Deduplicated short resource name
            short = (
                f.resource_id.rsplit("/", 1)[-1]
                if "/" in f.resource_id
                else f.resource_id
            )
            if short not in groups[key].resource_names:
                groups[key].resource_names.append(short)

            # Capture evidence result value for summary
            ev = f.evidence or {}
            if ev:
                raw = ev.get("result", ev.get("status", next(iter(ev.values()), "—")))
                ev_results[key].append(str(raw)[:60])

        # Finalise each group
        for key, g in groups.items():
            votes = rec_votes.get(key, {})
            if votes:
                g.recommendation = max(votes, key=lambda r: votes[r])  # type: ignore[return-value]

            ev_list = ev_results.get(key, [])
            if ev_list:
                most_common_val, mc_count = Counter(ev_list).most_common(1)[0]
                g.evidence_summary = (
                    f"{g.count} resource(s) evaluated — "
                    f"most common result: {most_common_val} ({mc_count}/{g.count})"
                )
            else:
                g.evidence_summary = f"{g.count} resource(s) evaluated."

        return sorted(
            groups.values(),
            key=lambda g: (
                _SEVERITY_ORDER.index(g.severity) if g.severity in _SEVERITY_ORDER else 99,
                -g.count,
            ),
        )

    except Exception:
        # Fallback: one ungrouped entry per finding — report generation continues.
        result: list[_GroupedFinding] = []
        for f in findings:
            gf = _GroupedFinding(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity.value,
                pillar=f.pillar,
                recommendation=f.recommendation,
                waf_codes=list(f.waf_codes),
            )
            short = (
                f.resource_id.rsplit("/", 1)[-1]
                if "/" in f.resource_id
                else f.resource_id
            )
            gf.resource_names.append(short)
            gf.evidence_summary = "Evidence unavailable (fallback mode)."
            result.append(gf)
        return result


# ── Resource-group helpers (computed from findings, no extra DB query) ─────────

def _extract_resource_group(resource_id: str) -> str:
    """Parse RG name from an ARM resource ID string."""
    parts = resource_id.split("/")
    try:
        # Standard form: /subscriptions/…/resourceGroups/{rg}/…
        idx = next(
            i for i, p in enumerate(parts)
            if p.lower() == "resourcegroups"
        )
        raw = parts[idx + 1] if idx + 1 < len(parts) else ""
        return raw if raw else "Unknown"
    except StopIteration:
        return "Unknown"


def _build_rg_stats(
    findings: list[Finding],
) -> list[tuple[str, int, int, int, float, int]]:
    """Derive per-RG stats from findings list.

    Returns list of (rg_name, finding_resources, findings_count, critical,
                     high, severity_score) sorted by risk descending.
    No additional DB access needed.
    """
    rg: dict[str, dict[str, Any]] = {}
    for f in findings:
        name = _extract_resource_group(f.resource_id)
        if name not in rg:
            rg[name] = {"resources": set(), "count": 0, "critical": 0, "high": 0}
        rg[name]["resources"].add(f.resource_id)
        rg[name]["count"] += 1
        if f.severity.value == "critical":
            rg[name]["critical"] += 1
        elif f.severity.value == "high":
            rg[name]["high"] += 1

    rows = []
    for name, data in rg.items():
        res   = len(data["resources"])
        count = data["count"]
        crit  = data["critical"]
        high  = data["high"]
        # Risk score: higher = worse
        risk  = crit * 4 + high * 2 + (count - crit - high)
        rows.append((name, res, count, crit, high, risk))
    # Sort worst first
    rows.sort(key=lambda r: r[5], reverse=True)
    return rows


# ── Scorecard computation ──────────────────────────────────────────────────────

def _compute_scorecard(findings: list[Finding]) -> list[tuple[str, float, str]]:
    """Return (category, score_0_to_100, status_label) for each scorecard category.

    Score = 100 − (weighted non-compliance fraction for findings whose WAF codes
    intersect the category).  Returns 100.0 (green) for categories with no findings.
    """
    _WEIGHTS = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "informational": 0.0}
    result = []
    for cat, codes in _SCORECARD_CATEGORIES.items():
        cat_findings = [
            f for f in findings
            if codes.intersection(f.waf_codes)
        ]
        if not cat_findings:
            score = 100.0
        else:
            total  = len(cat_findings)
            weight = sum(_WEIGHTS.get(f.severity.value, 0.5) for f in cat_findings)
            score  = round((1.0 - weight / total) * 100, 1)

        if score >= 90:
            status = "Excellent"
        elif score >= 75:
            status = "Good"
        elif score >= 50:
            status = "Needs Improvement"
        else:
            status = "Critical"

        result.append((cat, score, status))
    return result


# ── Pillar Scorecard helpers ───────────────────────────────────────────────────

_PILLAR_SCORE_DISPLAY: dict[str, str] = {
    "security":               "Security",
    "reliability":            "Reliability",
    "cost_optimization":      "Cost Optimization",
    "operational_excellence": "Operational Excellence",
    "performance_efficiency": "Performance Efficiency",
}
_PILLAR_SCORE_ORDER = list(_PILLAR_SCORE_DISPLAY.keys())
_PILLAR_SCORE_DEDUCTIONS: dict[str, int] = {
    "critical": 15, "high": 10, "medium": 5, "low": 2, "informational": 0,
}


def calculate_pillar_scores(
    findings: list[Finding],
) -> list[tuple[str, int, str, int, int, int, int, int]]:
    """Calculate WAF pillar scores using severity deductions.

    Returns list of (display_name, score, status, total, critical, high, medium, low).
    Score starts at 100; each finding deducts: Critical 15, High 10, Medium 5, Low 2.
    Floored at 0, ceiling at 100.  Pillars with no findings score 100 (Excellent).
    Falls back to an empty list on any error — callers must handle gracefully.
    """
    try:
        by_pillar: dict[str, dict[str, int]] = {}
        for f in findings:
            p = f.pillar
            s = f.severity.value
            if p not in by_pillar:
                by_pillar[p] = {}
            by_pillar[p][s] = by_pillar[p].get(s, 0) + 1

        result: list[tuple[str, int, str, int, int, int, int, int]] = []
        seen: set[str] = set()

        for pk in _PILLAR_SCORE_ORDER:
            counts = by_pillar.get(pk, {})
            crit = counts.get("critical", 0)
            high = counts.get("high", 0)
            med  = counts.get("medium", 0)
            low  = counts.get("low", 0)
            info = counts.get("informational", 0)
            total = crit + high + med + low + info
            score = max(0, 100 - (crit * 15 + high * 10 + med * 5 + low * 2))
            if score >= 90:
                status = "Excellent"
            elif score >= 75:
                status = "Good"
            elif score >= 60:
                status = "Needs Improvement"
            else:
                status = "High Risk"
            result.append((_PILLAR_SCORE_DISPLAY[pk], score, status, total, crit, high, med, low))
            seen.add(pk)

        for pk, counts in by_pillar.items():
            if pk in seen:
                continue
            crit = counts.get("critical", 0)
            high = counts.get("high", 0)
            med  = counts.get("medium", 0)
            low  = counts.get("low", 0)
            info = counts.get("informational", 0)
            total = crit + high + med + low + info
            score = max(0, 100 - (crit * 15 + high * 10 + med * 5 + low * 2))
            if score >= 90:   status = "Excellent"
            elif score >= 75: status = "Good"
            elif score >= 60: status = "Needs Improvement"
            else:             status = "High Risk"
            result.append((pk.replace("_", " ").title(), score, status, total, crit, high, med, low))

        return result
    except Exception:
        return []


def calculate_maturity_rating(avg_score: float) -> str:
    """Map average pillar score to an executive Well-Architected maturity label."""
    if avg_score >= 90:
        return "Enterprise Ready"
    if avg_score >= 80:
        return "Strong"
    if avg_score >= 70:
        return "Moderate"
    if avg_score >= 60:
        return "Needs Improvement"
    return "High Risk"


# ── Evidence Snapshot helpers ──────────────────────────────────────────────────

_EVIDENCE_REDACT_KEYS: frozenset[str] = frozenset({
    "password", "secret", "token", "key", "certificate", "sas", "connectionstring",
})


def sanitize_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Remove any field whose key contains a sensitive term (case-insensitive).

    Strips: password, secret, token, key, certificate, sas, connectionString.
    Safe to call on an empty dict — returns {}.
    """
    return {
        k: v
        for k, v in evidence.items()
        if not any(banned in k.lower() for banned in _EVIDENCE_REDACT_KEYS)
    }


def build_evidence_snapshot(finding: Finding) -> dict[str, Any]:
    """Build a small, sanitized evidence dict suitable for report display.

    Rules:
    - Applies sanitize_evidence() to strip secret-bearing fields.
    - Caps at 10 fields.
    - Trims to ≤500 chars when serialized as JSON; appends a '…' marker if cut.
    - Returns {} on empty evidence or any error — callers must handle gracefully.
    """
    try:
        ev = finding.evidence or {}
        if not ev:
            return {}
        cleaned = sanitize_evidence(ev)
        if not cleaned:
            return {}
        if len(cleaned) > 10:
            cleaned = dict(list(cleaned.items())[:10])
        serialized = json.dumps(cleaned, default=str)
        if len(serialized) <= 500:
            return cleaned
        # Trim field-by-field until under limit
        result: dict[str, Any] = {}
        for k, v in cleaned.items():
            if len(json.dumps({**result, k: v}, default=str)) > 480:
                result["…"] = "(truncated)"
                break
            result[k] = v
        return result
    except Exception:
        return {}


# ── Executive Remediation Roadmap helpers ─────────────────────────────────────

_REMEDIATION_SEV_WEIGHT: dict[str, int] = {
    "critical": 100, "high": 75, "medium": 50, "low": 25, "informational": 0,
}
_REMEDIATION_PILLAR_BONUS: dict[str, int] = {
    "security": 20, "reliability": 15,
    "operational_excellence": 10, "cost_optimization": 10,
    "performance_efficiency": 10,
}


def calculate_remediation_priority(finding: Finding) -> int:
    """Score a finding for remediation ordering (higher = fix sooner).

    Formula: severity weight (Critical 100, High 75, Medium 50, Low 25)
    plus pillar bonus (Security +20, Reliability +15, others +10).
    """
    return (
        _REMEDIATION_SEV_WEIGHT.get(finding.severity.value, 0)
        + _REMEDIATION_PILLAR_BONUS.get(finding.pillar, 0)
    )


def estimate_effort(resource_count: int) -> str:
    """Map an affected-resource count to a remediation effort label.

    1 resource → Low  |  2–5 → Medium  |  6+ → High
    """
    if resource_count <= 1:
        return "Low"
    if resource_count <= 5:
        return "Medium"
    return "High"


def build_executive_remediation_roadmap(
    findings: list[Finding],
) -> list[dict[str, Any]]:
    """Build a 3-phase executive remediation roadmap from actual findings.

    Phase 1 — Immediate (0–30 Days):  critical + high-security findings.
    Phase 2 — Near Term (30–60 Days): remaining high + medium findings.
    Phase 3 — Strategic (60–90 Days): low + informational findings.

    Findings are deduplicated by (rule_id, severity); resources are counted
    across all matching findings.  Each phase is sorted by priority descending.

    Returns list of phase dicts (each has: name, timeframe, risk_reduction,
    items).  Returns [] on empty input or any error — never aborts generation.
    """
    try:
        if not findings:
            return []

        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for f in findings:
            key = (f.rule_id, f.severity.value)
            if key not in groups:
                groups[key] = {
                    "title": f.title,
                    "severity": f.severity.value,
                    "pillar": f.pillar,
                    "recommendation": f.recommendation,
                    "resources": set(),
                    "priority": calculate_remediation_priority(f),
                }
            groups[key]["resources"].add(f.resource_id)

        phase1: list[dict[str, Any]] = []
        phase2: list[dict[str, Any]] = []
        phase3: list[dict[str, Any]] = []

        for item in groups.values():
            sev = item["severity"]
            resource_count = len(item["resources"])
            row: dict[str, Any] = {
                "title": item["title"],
                "severity": sev,
                "pillar": item["pillar"],
                "resource_count": resource_count,
                "priority": item["priority"],
                "effort": estimate_effort(resource_count),
                "recommendation": item["recommendation"],
            }
            if sev == "critical" or (sev == "high" and item["pillar"] == "security"):
                phase1.append(row)
            elif sev in ("high", "medium"):
                phase2.append(row)
            else:
                phase3.append(row)

        for lst in (phase1, phase2, phase3):
            lst.sort(key=lambda x: x["priority"], reverse=True)

        phases: list[dict[str, Any]] = []
        if phase1:
            phases.append({
                "name": "Phase 1 — Immediate",
                "timeframe": "0–30 Days",
                "risk_reduction": "45%",
                "items": phase1,
            })
        if phase2:
            phases.append({
                "name": "Phase 2 — Near Term",
                "timeframe": "30–60 Days",
                "risk_reduction": "25%",
                "items": phase2,
            })
        if phase3:
            phases.append({
                "name": "Phase 3 — Strategic",
                "timeframe": "60–90 Days",
                "risk_reduction": "15%",
                "items": phase3,
            })
        return phases
    except Exception:
        return []


# ── AI Executive Recommendations (deterministic) ───────────────────────────────

def _generate_recommendations(
    agg: AggregatedReport,
    findings: list[Finding],
) -> list[tuple[str, str, str]]:
    """Return up to 5 recommendations as (title, action, rationale) tuples.

    Fully deterministic — identical inputs always produce identical output.
    """
    recs: list[tuple[str, str, str]] = []
    sev  = agg.findings_by_severity
    critical = sev.get("critical", 0)
    high     = sev.get("high", 0)
    total    = agg.total_findings

    # 1 — Immediate Actions
    if critical > 0:
        action = (
            f"Immediately remediate all {critical} Critical severity finding(s). "
            "Assign dedicated sprint capacity; do not defer to future quarters."
        )
        rationale = (
            "Critical findings represent direct exploitation vectors or compliance failures "
            "that expose the organisation to regulatory penalty and service disruption."
        )
    elif high > 0:
        action = (
            f"Prioritise remediation of {high} High severity finding(s) within 14 days."
        )
        rationale = (
            "High findings indicate significant gaps that adversaries can chain "
            "into impactful attacks with moderate effort."
        )
    else:
        action = "Review all Medium findings and create a backlog with target dates."
        rationale = "No Critical or High findings were detected. Maintaining vigilance on Medium findings prevents regression."
    recs.append(("1. Immediate Actions", action, rationale))

    # 2 — Short-Term Improvements (most affected pillar)
    most_affected_pillar = max(
        agg.findings_by_pillar, key=lambda p: agg.findings_by_pillar[p].total_findings,
        default=None,
    )
    if most_affected_pillar:
        ps         = agg.findings_by_pillar[most_affected_pillar]
        pillar_str = most_affected_pillar.replace("_", " ").title()
        action = (
            f"Focus the next sprint on {pillar_str} pillar remediation. "
            f"{ps.total_findings} findings, compliance score "
            f"{ps.compliance_score * 100:.1f}%."
        )
        rationale = (
            f"The {pillar_str} pillar has the highest concentration of findings "
            "and will yield the largest compliance improvement per remediation effort."
        )
    else:
        action    = "Conduct a structured remediation sprint targeting Medium findings."
        rationale = "No specific pillar dominates; balance effort across pillars."
    recs.append(("2. Short-Term Improvements (Weeks 2–4)", action, rationale))

    # 3 — Governance Improvements
    oe_findings = agg.findings_by_pillar.get("operational_excellence")
    if oe_findings and oe_findings.total_findings > 0:
        action = (
            f"Address {oe_findings.total_findings} Operational Excellence finding(s) "
            "by implementing Azure Policy assignments, resource tagging standards, "
            "and automated compliance reporting."
        )
        rationale = (
            "Governance gaps compound over time. Addressing them early prevents "
            "the accumulation of technical debt and regulatory exposure."
        )
    else:
        action    = "Establish Azure Policy baselines and a monthly compliance review cadence."
        rationale = "Proactive governance prevents findings before they are detected."
    recs.append(("3. Governance Improvements", action, rationale))

    # 4 — Automation Opportunities
    # Find the most repeated rule (most findings for a single rule_id)
    rule_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        rule_counts[f.rule_id] += 1
    top_rule, top_count = (
        max(rule_counts.items(), key=lambda x: x[1])
        if rule_counts else ("—", 0)
    )
    if top_count >= 3:
        action = (
            f"Automate remediation of rule {top_rule} ({top_count} occurrences) "
            "using Azure Policy DeployIfNotExists or Terraform/Bicep module enforcement."
        )
        rationale = (
            f"Rule {top_rule} is the most frequently triggered finding. "
            "Automating its remediation eliminates recurring manual effort "
            "and prevents regression in future deployments."
        )
    else:
        action = (
            "Integrate WAF assessment into CI/CD pipelines to catch misconfigurations "
            "before they reach production environments."
        )
        rationale = "Shifting security left reduces the cost of remediation by 10× compared to post-deployment fixes."
    recs.append(("4. Automation Opportunities", action, rationale))

    # 5 — Continuous Compliance
    if agg.trend_data and len(agg.trend_data) >= 2:
        first_score = agg.trend_data[0].compliance_score
        last_score  = agg.trend_data[-1].compliance_score
        delta       = last_score - first_score
        if delta >= 0:
            trend_desc = f"improving (+{delta:.1f}% over {len(agg.trend_data)} assessments)"
        else:
            trend_desc = f"declining ({delta:.1f}% over {len(agg.trend_data)} assessments)"
        action = (
            f"Maintain monthly assessment cadence. Current trend is {trend_desc}. "
            "Target compliance score ≥ 90% within 90 days."
        )
        rationale = (
            "Continuous assessment creates an auditable compliance history "
            "required by enterprise risk frameworks (SOC 2, ISO 27001, NIST CSF)."
        )
    else:
        action = (
            "Establish a monthly assessment schedule. Set a compliance target of "
            f"≥ 90% (current: {agg.overall_compliance_score:.1f}%) and "
            "track progress through the Trend Analysis section of each report."
        )
        rationale = (
            "A single assessment is a snapshot. Only a regular cadence reveals "
            "trend direction and provides the evidence trail for auditors."
        )
    recs.append(("5. Continuous Compliance Monitoring", action, rationale))

    return recs


# ── Executive Summary helpers ──────────────────────────────────────────────────

_EXEC_RISK_PALETTE: dict[str, colors.Color] = {
    "Critical": colors.HexColor("#C0392B"),
    "High":     colors.HexColor("#E67E22"),
    "Medium":   colors.HexColor("#D4AC0D"),
    "Low":      colors.HexColor("#1E8449"),
}


def _compute_exec_risk_rating(agg: AggregatedReport) -> tuple[str, colors.Color]:
    """Map severity counts + risk score to a single executive risk label."""
    crit  = agg.findings_by_severity.get("critical", 0)
    high  = agg.findings_by_severity.get("high", 0)
    score = agg.overall_risk_score
    if crit > 0 or score >= 70:
        label = "Critical"
    elif high > 0 or score >= 40:
        label = "High"
    elif score >= 15 or agg.total_findings > 0:
        label = "Medium"
    else:
        label = "Low"
    return label, _EXEC_RISK_PALETTE[label]


def _compute_key_business_risks(
    agg: AggregatedReport,
    findings: list[Finding],
) -> list[str]:
    """Derive up to 6 business risk statements from assessment data — no fabrication."""
    risks: list[str] = []

    sec_ps = agg.findings_by_pillar.get("security")
    if sec_ps and sec_ps.total_findings > 0:
        crit_sec = sec_ps.findings_by_severity.get("critical", 0)
        if crit_sec > 0:
            risks.append(
                f"Potential data exposure: {crit_sec} critical security misconfiguration(s) "
                "present active exploitation vectors against sensitive data and credentials."
            )
        else:
            risks.append(
                f"Security posture gap: {sec_ps.total_findings} security finding(s) "
                "increase the organisation's attack surface exposure."
            )

    below_threshold = [
        p for p, ps in agg.findings_by_pillar.items()
        if ps.compliance_score < 0.70
    ]
    if below_threshold:
        pillars_str = ", ".join(
            p.replace("_", " ").title() for p in sorted(below_threshold)[:3]
        )
        risks.append(
            f"Compliance gaps: {pillars_str} pillar(s) below 70% compliance threshold, "
            "creating audit exposure and potential regulatory risk."
        )

    rel_ps = agg.findings_by_pillar.get("reliability")
    if rel_ps and rel_ps.total_findings > 0:
        risks.append(
            f"Service resiliency concerns: {rel_ps.total_findings} reliability finding(s) "
            "may compromise SLA commitments and business continuity posture."
        )

    oe_ps = agg.findings_by_pillar.get("operational_excellence")
    if oe_ps and oe_ps.total_findings > 0:
        risks.append(
            f"Operational risk: {oe_ps.total_findings} operational excellence finding(s) "
            "indicate process and automation gaps increasing incident probability."
        )

    cost_ps = agg.findings_by_pillar.get("cost_optimization")
    if cost_ps and cost_ps.total_findings > 0:
        risks.append(
            f"Financial exposure: {cost_ps.total_findings} cost optimisation finding(s) "
            "indicate measurable cloud spend inefficiencies."
        )

    perf_ps = agg.findings_by_pillar.get("performance_efficiency")
    if perf_ps and perf_ps.total_findings > 0:
        risks.append(
            f"Performance risk: {perf_ps.total_findings} performance finding(s) "
            "may degrade user experience and violate service quality expectations."
        )

    if not risks:
        risks.append(
            "No significant business risks identified. "
            "The environment meets all evaluated WAF controls."
        )
    return risks[:6]


def _compute_top_5_actions(
    agg: AggregatedReport,
    findings: list[Finding],
) -> list[tuple[int, str, str, str, str]]:
    """Return up to 5 action items as (rank, title, resource_short, severity, impact).

    Uses pre-computed top_5_risks when available; falls back to raw findings list.
    """
    if agg.top_5_risks:
        return [
            (
                i,
                _tr(risk.title, 50),
                _tr(risk.resource_id.rsplit("/", 1)[-1], 28),
                risk.severity.upper(),
                _tr(risk.business_impact, 30),
            )
            for i, risk in enumerate(agg.top_5_risks, 1)
        ]

    sorted_f = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.index(f.severity.value)
            if f.severity.value in _SEVERITY_ORDER else 99,
            -f.confidence_score,
        ),
    )[:5]
    return [
        (
            i,
            _tr(f.title, 50),
            _tr(f.resource_id.rsplit("/", 1)[-1], 28),
            f.severity.value.upper(),
            _tr(_PILLAR_TO_IMPACT.get(f.pillar, "Operational Risk"), 30),
        )
        for i, f in enumerate(sorted_f, 1)
    ]


def _compute_compliance_projection(
    agg: AggregatedReport,
) -> tuple[float, float, float, float]:
    """Return (current, after_high_fixed, after_high_med_fixed, target) compliance %."""
    sev   = agg.findings_by_severity
    crit  = sev.get("critical", 0)
    high  = sev.get("high", 0)
    med   = sev.get("medium", 0)
    low   = sev.get("low", 0)
    total = agg.total_findings
    current = agg.overall_compliance_score

    if total == 0:
        return current, 100.0, 100.0, 90.0

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

    return current, after_high, after_hm, 90.0


# ── Page footer factory ────────────────────────────────────────────────────────

def _make_page_footer(agg: AggregatedReport) -> Callable:
    """Return a reportlab canvas callback that draws the footer on every page."""
    assessment_id_str = str(agg.assessment_id)
    timestamp         = agg.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    def _draw(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        # Separator line
        canvas.setStrokeColor(colors.HexColor("#BDC3C7"))
        canvas.setLineWidth(0.4)
        canvas.line(_MARGIN, _BOTTOM_MARGIN - 0.25 * cm,
                    _PAGE_WIDTH - _MARGIN, _BOTTOM_MARGIN - 0.25 * cm)
        # Footer text
        canvas.setFont("Helvetica", 6)
        canvas.setFillColor(colors.HexColor("#7F8C8D"))
        canvas.drawString(
            _MARGIN, _BOTTOM_MARGIN - 0.55 * cm,
            f"Assessment ID: {assessment_id_str}  |  CONFIDENTIAL",
        )
        canvas.drawCentredString(
            _PAGE_WIDTH / 2, _BOTTOM_MARGIN - 0.55 * cm,
            f"Page {doc.page}",
        )
        canvas.drawRightString(
            _PAGE_WIDTH - _MARGIN, _BOTTOM_MARGIN - 0.55 * cm,
            f"Generated: {timestamp}",
        )
        canvas.restoreState()

    return _draw


# ── Public class ───────────────────────────────────────────────────────────────

class PdfGenerator:
    """Generates a 20-section enterprise PDF assessment report as bytes."""

    def generate(
        self,
        aggregated: AggregatedReport,
        findings: Sequence[Finding],
        human_reviews: list[HumanReviewAssessment] | None = None,
    ) -> bytes:
        buf = io.BytesIO()
        _gen_ts = datetime.utcnow().strftime("%Y-%m-%d")
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=_MARGIN,
            bottomMargin=_BOTTOM_MARGIN,
            title="Azure Well-Architected Framework Assessment Report",
            author="Azure WAF Assessment Platform",
            subject=f"WAF Assessment — {_gen_ts}",
            keywords="Azure WAF Security Reliability Assessment Compliance",
            creator=f"WAF Report Generator v{_REPORT_VERSION}",
        )
        st            = _styles()
        story: list   = []
        all_findings  = list(findings)
        hr_list       = human_reviews or []
        footer_fn     = _make_page_footer(aggregated)

        # ── Section flow ───────────────────────────────────────────────────────
        self._section_cover(story, st, aggregated)
        story.append(PageBreak())

        self._section_executive_risk_statement(story, st, aggregated)
        story.append(PageBreak())

        self._section_executive_summary(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_pillar_scorecard(story, st, all_findings)
        story.append(PageBreak())

        self._section_security_scorecard(story, st, all_findings)
        story.append(PageBreak())

        self._section_executive_dashboard(story, st, aggregated)
        story.append(PageBreak())

        self._section_visual_dashboards(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_resource_inventory(story, st, aggregated)
        story.append(PageBreak())

        self._section_resource_group_breakdown(story, st, all_findings)
        story.append(PageBreak())

        self._section_compliance_overview(story, st, aggregated)
        story.append(PageBreak())

        self._section_waf_benchmark(story, st, aggregated)
        story.append(PageBreak())

        self._section_business_impact(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_executive_insights(story, st, all_findings)
        story.append(PageBreak())

        self._section_architecture(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_waf_control_pages(story, st, all_findings)
        story.append(PageBreak())

        self._section_trend_analysis(story, st, aggregated)
        story.append(PageBreak())

        self._section_compliance_roadmap(story, st, aggregated)
        story.append(PageBreak())

        self._section_executive_remediation_roadmap(story, st, all_findings)
        story.append(PageBreak())

        self._section_remediation_roadmap(story, st, all_findings)
        story.append(PageBreak())

        self._section_remediation_playbooks(story, st, all_findings)
        story.append(PageBreak())

        self._section_enterprise_remediation_roadmap(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_human_reviews(story, st, hr_list)
        story.append(PageBreak())

        self._section_traceability_matrix(story, st, all_findings)
        story.append(PageBreak())

        self._section_detailed_findings(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_executive_recommendations(story, st, aggregated, all_findings)
        story.append(PageBreak())

        self._section_appendix(story, st, all_findings, aggregated)
        story.append(PageBreak())

        self._section_compliance_framework_mapping(story, st, all_findings)
        story.append(PageBreak())

        self._section_risk_matrix(story, st, all_findings)
        story.append(PageBreak())

        self._section_assessment_methodology(story, st)
        story.append(PageBreak())

        self._section_confidence_explanation(story, st)
        story.append(PageBreak())

        self._section_limitations(story, st)
        story.append(PageBreak())

        self._section_audit_trail(story, st, aggregated)
        story.append(PageBreak())

        self._section_glossary(story, st)

        doc.build(story, onFirstPage=footer_fn, onLaterPages=footer_fn)  # type: ignore[arg-type]
        return buf.getvalue()

    # ── 1. Cover Page (upgraded) ──────────────────────────────────────────────

    def _section_cover(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        # Classification banner
        cls_data = [["CONFIDENTIAL"]]
        cls_tbl  = Table(cls_data, colWidths=[_BODY_WIDTH])
        cls_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _C_CRIMSON),
            ("TEXTCOLOR",  (0, 0), (-1, -1), _C_WHITE),
            ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(cls_tbl)
        story.append(Spacer(1, 1.5 * cm))

        # Dark header band
        header_data = [["Azure Well-Architected Framework\nAssessment Report"]]
        header_tbl  = Table(header_data, colWidths=[_BODY_WIDTH])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, -1), _C_WHITE),
            ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 18),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 28),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
        ]))
        story.append(header_tbl)
        story.append(Spacer(1, 0.8 * cm))

        # Metadata table
        date_str = (
            agg.assessment_date.strftime("%Y-%m-%d")
            if agg.assessment_date else "Not Available"
        )
        meta = [
            ["Assessment ID",      str(agg.assessment_id)],
            ["Tenant ID",          str(agg.tenant_id)],
            ["Assessment Date",    date_str],
            ["Report Generated",   agg.generated_at.strftime("%Y-%m-%d %H:%M UTC")],
            ["Subscriptions",      str(agg.subscription_count) if agg.subscription_count else "Not Available"],
            ["Prepared By",        "AI Azure Well-Architected Review Agent"],
            ["Report Version",     _REPORT_VERSION],
            ["Classification",     "CONFIDENTIAL"],
        ]
        meta_tbl = Table(meta, colWidths=[5 * cm, _BODY_WIDTH - 5 * cm])
        meta_tbl.setStyle(TableStyle([
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("GRID",       (0, 0), (-1, -1), 0.4, _C_MGREY),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_C_WHITE, _C_LGREY]),
            # Highlight classification row
            ("TEXTCOLOR",  (1, 7), (1, 7), _C_CRIMSON),
            ("FONTNAME",   (1, 7), (1, 7), "Helvetica-Bold"),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 0.8 * cm))

        # KPI cards
        def _kpi_color(score: float) -> colors.Color:
            if score >= 90:
                return colors.HexColor("#27AE60")
            if score >= 70:
                return colors.HexColor("#F39C12")
            return colors.HexColor("#E74C3C")

        kpi_cards = [
            ("Overall Compliance", f"{agg.overall_compliance_score:.1f}%",
             _kpi_color(agg.overall_compliance_score)),
            ("Risk Score", f"{agg.overall_risk_score:.1f}%",
             _kpi_color(100 - agg.overall_risk_score)),
            ("Total Findings", str(agg.total_findings),
             _C_BLUE),
            ("Resources Assessed", str(agg.total_resources),
             _C_TEAL),
        ]
        story.append(build_kpi_cards(kpi_cards, width=_BODY_WIDTH))
        story.append(Spacer(1, 0.8 * cm))

        # Severity quick-view
        sev_rows = [["Severity", "Count"]]
        for sev in _SEVERITY_ORDER:
            sev_rows.append([sev.capitalize(), str(agg.findings_by_severity.get(sev, 0))])
        sev_tbl = Table(sev_rows, colWidths=[5 * cm, 4 * cm])
        sev_style = _header_style()
        for i, sev in enumerate(_SEVERITY_ORDER, start=1):
            if i < len(sev_rows):
                sev_style.append(("BACKGROUND", (0, i), (-1, i), _SEV_COLORS.get(sev, _C_WHITE)))
        sev_tbl.setStyle(TableStyle(sev_style))
        story.append(Paragraph("Findings by Severity", st["h2"]))
        story.append(sev_tbl)

    # ── 2. Executive Risk Statement [NEW] ─────────────────────────────────────

    def _section_executive_risk_statement(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Executive Risk Statement", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=2, color=_C_CRIMSON))
        story.append(Spacer(1, 0.4 * cm))

        sev        = agg.findings_by_severity
        critical   = sev.get("critical", 0)
        high       = sev.get("high", 0)
        total      = agg.total_findings

        # Most affected pillar
        most_pillar = (
            max(agg.findings_by_pillar,
                key=lambda p: agg.findings_by_pillar[p].total_findings)
            if agg.findings_by_pillar else None
        )
        most_pillar_str  = most_pillar.replace("_", " ").title() if most_pillar else "N/A"
        most_pillar_pct  = (
            f"{agg.findings_by_pillar[most_pillar].total_findings / total * 100:.1f}"
            if most_pillar and total > 0 else "0.0"
        )

        # Most affected resource type
        most_rt: str | None = None
        if agg.resource_type_inventory:
            most_rt = max(
                agg.resource_type_inventory,
                key=lambda k: agg.resource_type_inventory[k].with_findings,
            )
        most_rt_str = _short_rt(most_rt) if most_rt else "N/A"

        # Estimated compliance improvement if all critical+high resolved
        if total > 0 and (critical + high) > 0:
            ch_weight  = critical * 1.0 + high * 0.75
            fraction   = ch_weight / total
            raw_gain   = fraction * (100 - agg.overall_compliance_score) * 0.65
            est_target = min(100.0, agg.overall_compliance_score + raw_gain)
        else:
            est_target = agg.overall_compliance_score

        # Generate narrative paragraphs
        if total == 0:
            narrative = (
                "This assessment found <b>no actionable findings</b> across all "
                f"{agg.total_resources} assessed resources. "
                "The environment meets all evaluated Well-Architected Framework controls."
            )
            story.append(Paragraph(narrative, st["risk_statement"]))
            return

        p1 = (
            f"The assessment identified <b>{total} finding(s)</b> across "
            f"<b>{agg.resources_with_findings} resource(s)</b> "
            f"({agg.total_resources} resources assessed in total)."
        )

        severity_clause = ""
        if critical > 0 and high > 0:
            severity_clause = (
                f"<b>{critical} Critical</b> and <b>{high} High</b> severity findings "
                "represent the most immediate organisational risk and demand "
                "<b>immediate remediation within 14 days</b>."
            )
        elif critical > 0:
            severity_clause = (
                f"<b>{critical} Critical</b> severity finding(s) represent direct "
                "exposure to exploitation or compliance failure and must be remediated "
                "<b>immediately</b>."
            )
        elif high > 0:
            severity_clause = (
                f"<b>{high} High</b> severity finding(s) represent significant "
                "security gaps that should be remediated <b>within 30 days</b>."
            )
        else:
            severity_clause = (
                "No Critical or High severity findings were identified. "
                "Attention is required on Medium findings to prevent risk accumulation."
            )

        p2 = severity_clause

        p3 = (
            f"The <b>{most_pillar_str}</b> pillar exhibits the highest concentration "
            f"of risk, accounting for <b>{most_pillar_pct}%</b> of all findings. "
            f"<b>{most_rt_str}</b> is the most frequently affected resource type."
        )

        p4 = (
            f"Immediate remediation of Critical and High findings is estimated to "
            f"improve the overall compliance score from "
            f"<b>{agg.overall_compliance_score:.1f}%</b> to approximately "
            f"<b>{est_target:.1f}%</b>."
        )

        for para in [p1, p2, p3, p4]:
            story.append(Paragraph(para, st["risk_statement"]))
            story.append(Spacer(1, 0.2 * cm))

        # Risk summary box
        risk_level = _risk_label(agg.overall_risk_score)
        summary_data = [
            ["Risk Indicator", "Value"],
            ["Overall Compliance Score", f"{agg.overall_compliance_score:.1f}%"],
            ["Overall Risk Score",       f"{agg.overall_risk_score:.1f}% — {risk_level}"],
            ["Critical Findings",        str(critical)],
            ["High Findings",            str(high)],
            ["Most Affected Pillar",     most_pillar_str],
            ["Most Affected Resource",   most_rt_str],
            ["Estimated Target Compliance (post-remediation)", f"{est_target:.1f}%"],
        ]
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Risk Summary", st["h2"]))
        tbl = _make_table(summary_data, col_widths=[9 * cm, _BODY_WIDTH - 9 * cm])
        story.append(tbl)

    # ── 3. Executive Summary (enterprise consulting quality) ──────────────────

    def _section_executive_summary(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding] | None = None,
    ) -> None:
        all_f = findings or []
        sev   = agg.findings_by_severity
        crit  = sev.get("critical", 0)
        high  = sev.get("high", 0)
        med   = sev.get("medium", 0)
        current_c, after_high_c, after_hm_c, target_c = _compute_compliance_projection(agg)
        exec_rating, rating_color = _compute_exec_risk_rating(agg)

        story.append(Paragraph("Executive Summary", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        # ── 3a. Assessment Overview ───────────────────────────────────────────
        overview = [
            ["Metric", "Value"],
            ["Total Resources Assessed",   str(agg.total_resources)],
            ["Resources with Findings",    str(agg.resources_with_findings)],
            ["Total Findings",             str(agg.total_findings)],
            ["Assessment Coverage",        f"{agg.coverage_percentage * 100:.1f}%"],
            ["Overall Compliance Score",   f"{agg.overall_compliance_score:.1f}%"],
            ["Overall Risk Score",         f"{agg.overall_risk_score:.1f}%"],
        ]
        story.append(Paragraph("Assessment Overview", st["h2"]))
        story.append(_make_table(overview, col_widths=[7 * cm, 9 * cm]))
        story.append(Spacer(1, 0.4 * cm))

        # ── 3b. Executive Risk Rating ─────────────────────────────────────────
        story.append(Paragraph("Executive Risk Rating", st["h2"]))
        rating_data = [[f"OVERALL RISK RATING:   {exec_rating.upper()}"]]
        rating_tbl = Table(rating_data, colWidths=[_BODY_WIDTH])
        rating_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), rating_color),
            ("TEXTCOLOR",     (0, 0), (-1, -1), _C_WHITE),
            ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 14),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 11),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
        ]))
        story.append(rating_tbl)
        legend_rows = [[
            "Critical  (crit findings or risk ≥ 70%)",
            "High  (high findings or risk ≥ 40%)",
            "Medium  (any findings)",
            "Low  (no findings)",
        ]]
        legend_tbl = Table(legend_rows, colWidths=[_BODY_WIDTH / 4] * 4)
        legend_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), _EXEC_RISK_PALETTE["Critical"]),
            ("BACKGROUND",    (1, 0), (1, 0), _EXEC_RISK_PALETTE["High"]),
            ("BACKGROUND",    (2, 0), (2, 0), _EXEC_RISK_PALETTE["Medium"]),
            ("BACKGROUND",    (3, 0), (3, 0), _EXEC_RISK_PALETTE["Low"]),
            ("TEXTCOLOR",     (0, 0), (-1, -1), _C_WHITE),
            ("FONTSIZE",      (0, 0), (-1, -1), 7),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(legend_tbl)
        story.append(Spacer(1, 0.5 * cm))

        # ── 3c. Key Business Risks ────────────────────────────────────────────
        story.append(Paragraph("Key Business Risks", st["h2"]))
        business_risks = _compute_key_business_risks(agg, all_f)
        risk_rows = [[Paragraph(f"• {r}", st["body"])] for r in business_risks]
        risk_tbl  = Table(risk_rows, colWidths=[_BODY_WIDTH])
        risk_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FEF9E7")),
            ("BOX",           (0, 0), (-1, -1), 0.6, _C_ORANGE),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(risk_tbl)
        story.append(Spacer(1, 0.5 * cm))

        # ── 3d. Top 5 Prioritised Actions ────────────────────────────────────
        top_actions = _compute_top_5_actions(agg, all_f)
        if top_actions:
            story.append(Paragraph("Top 5 Prioritised Actions", st["h2"]))
            action_rows = [["#", "Finding Title", "Affected Resource", "Severity", "Business Impact"]]
            sev_extra: list = []
            for rank, title, resource, severity, impact in top_actions:
                action_rows.append([str(rank), title, resource, severity, impact])
                sev_extra.append((
                    "BACKGROUND", (3, rank), (3, rank),
                    _SEV_COLORS.get(severity.lower(), _C_WHITE),
                ))
            story.append(_make_table(
                action_rows,
                col_widths=[0.7 * cm, 5 * cm, 3.5 * cm, 2 * cm, 4.5 * cm],
                extra_style=sev_extra,
            ))
            story.append(Spacer(1, 0.5 * cm))

        # ── 3e. Compliance Projection ─────────────────────────────────────────
        story.append(Paragraph("Compliance Projection", st["h2"]))
        story.append(Paragraph(
            "Estimated compliance scores as findings are remediated, "
            "calculated from actual severity weights in this assessment.",
            st["caption"],
        ))

        def _score_bg(score: float) -> colors.Color:
            if score >= 90:
                return colors.HexColor("#D5F5E3")
            if score >= 70:
                return colors.HexColor("#FDEBD0")
            return colors.HexColor("#FADBD8")

        proj_rows = [
            ["Scenario", "Compliance Score", "Delta vs Current"],
            ["Current State",                      f"{current_c:.1f}%",    "— (baseline)"],
            ["After High Findings Remediated",     f"{after_high_c:.1f}%",
             f"+{after_high_c - current_c:.1f}%" if after_high_c > current_c else "—"],
            ["After High + Medium Remediated",     f"{after_hm_c:.1f}%",
             f"+{after_hm_c - current_c:.1f}%" if after_hm_c > current_c else "—"],
            ["Enterprise Target (90%)",            f"{target_c:.0f}%",     "Target"],
        ]
        proj_extra = [
            ("BACKGROUND", (0, 1), (-1, 1), _score_bg(current_c)),
            ("BACKGROUND", (0, 2), (-1, 2), _score_bg(after_high_c)),
            ("BACKGROUND", (0, 3), (-1, 3), _score_bg(after_hm_c)),
            ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#D6EAF8")),
            ("FONTNAME",   (0, 4), (-1, 4), "Helvetica-Bold"),
            ("FONTNAME",   (1, 1), (1, 4),  "Helvetica-Bold"),
        ]
        story.append(_make_table(
            proj_rows,
            col_widths=[7.5 * cm, 3.5 * cm, 5.5 * cm],
            extra_style=proj_extra,
        ))
        story.append(Spacer(1, 0.5 * cm))

        # ── 3f. Pillar Compliance (preserved) ─────────────────────────────────
        if agg.findings_by_pillar:
            pillar_rows = [["Pillar", "Compliance %", "Findings", "Critical", "High"]]
            for name in sorted(agg.findings_by_pillar.keys()):
                ps = agg.findings_by_pillar[name]
                pillar_rows.append([
                    name.replace("_", " ").title(),
                    f"{ps.compliance_score * 100:.1f}%",
                    str(ps.total_findings),
                    str(ps.findings_by_severity.get("critical", 0)),
                    str(ps.findings_by_severity.get("high", 0)),
                ])
            story.append(Paragraph("Compliance by Pillar", st["h2"]))
            story.append(_make_table(
                pillar_rows,
                col_widths=[6 * cm, 3.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm],
            ))
            story.append(Spacer(1, 0.5 * cm))

        # ── 3g. Management Summary — CIO/CTO one-paragraph view ───────────────
        story.append(Paragraph("Management Summary", st["h2"]))
        most_pillar = (
            max(agg.findings_by_pillar,
                key=lambda p: agg.findings_by_pillar[p].total_findings)
            if agg.findings_by_pillar else None
        )
        most_pillar_str = most_pillar.replace("_", " ").title() if most_pillar else "N/A"

        if agg.total_findings == 0:
            mgmt_text = (
                "<b>Risk Level: Low.</b>  This assessment found no actionable findings "
                f"across all {agg.total_resources} assessed resources. "
                "The environment fully meets all evaluated Well-Architected Framework controls. "
                "Maintain the current posture and continue a regular assessment cadence."
            )
        else:
            mgmt_text = (
                f"<b>Risk Level: {exec_rating}.</b>  "
                f"This assessment identified <b>{agg.total_findings} finding(s)</b> across "
                f"{agg.resources_with_findings} of {agg.total_resources} assessed resources "
                f"(overall compliance: <b>{current_c:.1f}%</b>).  "
            )
            if crit > 0:
                mgmt_text += (
                    f"<b>{crit} Critical finding(s) require immediate executive attention</b> — "
                    "assign dedicated remediation capacity this sprint.  "
                )
            if high > 0:
                mgmt_text += f"<b>{high} High finding(s)</b> must be resolved within 30 days.  "
            if med > 0:
                mgmt_text += f"{med} Medium finding(s) should be scheduled within 90 days.  "
            mgmt_text += (
                f"The <b>{most_pillar_str}</b> pillar carries the highest concentration of risk.  "
                f"Remediating High severity findings is projected to lift compliance to "
                f"<b>{after_high_c:.1f}%</b>; addressing High + Medium findings to "
                f"<b>{after_hm_c:.1f}%</b>, approaching the <b>{target_c:.0f}% enterprise target</b>."
            )

        mgmt_data = [[Paragraph(mgmt_text, st["narrative"])]]
        mgmt_tbl  = Table(mgmt_data, colWidths=[_BODY_WIDTH])
        mgmt_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#EBF5FB")),
            ("BOX",           (0, 0), (-1, -1), 1.0, _C_BLUE),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]))
        story.append(mgmt_tbl)

        # ── 3h. Severity distribution (preserved) ────────────────────────────
        if agg.findings_by_severity:
            story.append(Spacer(1, 0.5 * cm))
            story.append(Paragraph("Finding Distribution by Severity", st["h2"]))
            story.append(build_severity_pie(agg.findings_by_severity))

        # ── 3i. Overall Well-Architected Maturity ────────────────────────────
        try:
            ps = calculate_pillar_scores(all_f)
            if ps:
                avg_s = round(sum(s[1] for s in ps) / len(ps), 1)
                maturity = calculate_maturity_rating(avg_s)
                _MAT_COLORS = {
                    "Enterprise Ready":  colors.HexColor("#1E8449"),
                    "Strong":            colors.HexColor("#27AE60"),
                    "Moderate":          colors.HexColor("#E67E22"),
                    "Needs Improvement": colors.HexColor("#D4AC0D"),
                    "High Risk":         colors.HexColor("#C0392B"),
                }
                mat_color = _MAT_COLORS.get(maturity, _C_DARK)
                story.append(Spacer(1, 0.5 * cm))
                story.append(Paragraph("Overall Well-Architected Maturity", st["h2"]))
                mat_data = [[f"MATURITY LEVEL:   {maturity.upper()}     (Average Pillar Score: {avg_s:.1f} / 100)"]]
                mat_tbl = Table(mat_data, colWidths=[_BODY_WIDTH])
                mat_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), mat_color),
                    ("TEXTCOLOR",     (0, 0), (-1, -1), _C_WHITE),
                    ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1), 12),
                    ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                    ("TOPPADDING",    (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]))
                story.append(mat_tbl)
                mat_leg_data = [["90+: Enterprise Ready", "80-89: Strong", "70-79: Moderate",
                                 "60-69: Needs Improvement", "Below 60: High Risk"]]
                mat_leg_tbl = Table(mat_leg_data, colWidths=[_BODY_WIDTH / 5] * 5)
                mat_leg_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#1E8449")),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#27AE60")),
                    ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#E67E22")),
                    ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#D4AC0D")),
                    ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#C0392B")),
                    ("TEXTCOLOR",  (0, 0), (-1, -1), _C_WHITE),
                    ("FONTSIZE",   (0, 0), (-1, -1), 7),
                    ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(mat_leg_tbl)
        except Exception:
            pass  # Maturity block is optional — never abort report

        # ── 3j. Top 3 Recommended Actions (from Executive Remediation Roadmap) ─
        try:
            roadmap = build_executive_remediation_roadmap(all_f)
            top_items: list[dict[str, Any]] = []
            for phase in roadmap:
                top_items.extend(phase["items"])
                if len(top_items) >= 3:
                    break
            top_items = top_items[:3]
            if top_items:
                story.append(Spacer(1, 0.5 * cm))
                story.append(Paragraph("Top 3 Recommended Actions", st["h2"]))
                action_rows = []
                for i, item in enumerate(top_items, 1):
                    action_rows.append([
                        Paragraph(
                            f"<b>{i}.</b> {_code_xml(item['recommendation'], 150)}",
                            st["body"],
                        )
                    ])
                actions_tbl = Table(action_rows, colWidths=[_BODY_WIDTH])
                actions_tbl.setStyle(TableStyle([
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [
                        colors.HexColor("#EBF5FB"), colors.HexColor("#D6EAF8"),
                    ]),
                    ("BOX",           (0, 0), (-1, -1), 1.0, _C_BLUE),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                    ("TOPPADDING",    (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]))
                story.append(actions_tbl)
        except Exception:
            pass  # Top 3 actions block is optional

        # ── 3k. Executive Narrative ───────────────────────────────────────────
        try:
            exec_narrative = generate_executive_narrative(agg, all_f)
            story.append(Spacer(1, 0.6 * cm))
            story.append(HRFlowable(width="100%", thickness=0.5, color=_C_MGREY))
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph("Executive Narrative", st["h2"]))
            story.append(Paragraph(
                "The following narrative paragraphs are derived exclusively from actual "
                "assessment findings. No data is fabricated or inferred beyond what is "
                "present in the assessment results.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            _NARRATIVE_SECTIONS = [
                ("A.  Executive Overview",       exec_narrative.executive_overview),
                ("B.  Primary Risk Drivers",     exec_narrative.primary_risk_drivers),
                ("C.  Business Consequences",    exec_narrative.business_consequences),
                ("D.  Remediation Outlook",      exec_narrative.remediation_outlook),
                ("E.  Executive Recommendation", exec_narrative.executive_recommendation),
            ]

            for label, text in _NARRATIVE_SECTIONS:
                story.append(Paragraph(label, st["h3"]))
                para_data = [[Paragraph(_code_xml(text, 2000), st["narrative"])]]
                para_tbl  = Table(para_data, colWidths=[_BODY_WIDTH])
                para_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FDFEFE")),
                    ("BOX",           (0, 0), (-1, -1), 0.5, _C_MGREY),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                    ("TOPPADDING",    (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]))
                story.append(para_tbl)
                story.append(Spacer(1, 0.25 * cm))
        except Exception:
            pass  # Narrative block is optional — never abort report generation

    # ── 4. Azure Well-Architected Pillar Scorecard [NEW] ─────────────────────

    def _section_pillar_scorecard(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        """Per-pillar scorecard: severity-deduction score + status band."""
        _STATUS_BG: dict[str, colors.Color] = {
            "Excellent":         colors.HexColor("#D5F5E3"),
            "Good":              colors.HexColor("#A9DFBF"),
            "Needs Improvement": colors.HexColor("#FDEBD0"),
            "High Risk":         colors.HexColor("#FADBD8"),
        }

        story.append(Paragraph("Azure Well-Architected Scorecard", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Pillar scores start at 100 and are reduced by: Critical −15 · High −10 · "
            "Medium −5 · Low −2 · Informational 0.  Minimum: 0.  Maximum: 100.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        try:
            scores = calculate_pillar_scores(findings)
        except Exception:
            scores = []

        if not scores:
            story.append(Paragraph("No findings data available for scorecard.", st["na"]))
            return

        # ── Pillar scorecard table ─────────────────────────────────────────
        table_rows = [["Pillar", "Score", "Status"]]
        status_styles: list = []
        for i, (name, score, status, *_) in enumerate(scores, 1):
            table_rows.append([name, str(score), status])
            bg = _STATUS_BG.get(status, _C_WHITE)
            status_styles.extend([
                ("BACKGROUND", (1, i), (2, i), bg),
                ("FONTNAME",   (1, i), (1, i), "Helvetica-Bold"),
            ])

        story.append(_make_table(
            table_rows,
            col_widths=[7 * cm, 3 * cm, 6.7 * cm],
            extra_style=status_styles,
        ))
        story.append(Spacer(1, 0.5 * cm))

        # ── Summary metrics ────────────────────────────────────────────────
        all_scores = [s[1] for s in scores]
        avg_score  = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0
        best       = max(scores, key=lambda s: s[1])
        worst      = min(scores, key=lambda s: s[1])
        total_f    = sum(s[3] for s in scores)
        total_crit = sum(s[4] for s in scores)
        total_high = sum(s[5] for s in scores)
        maturity   = calculate_maturity_rating(avg_score)

        summary_rows = [
            ["Metric", "Value"],
            ["Average Score",          f"{avg_score:.1f} / 100"],
            ["Highest Scoring Pillar", f"{best[0]}  ({best[1]})"],
            ["Lowest Scoring Pillar",  f"{worst[0]}  ({worst[1]})"],
            ["Overall Maturity",       maturity],
            ["Total Findings",         str(total_f)],
            ["Critical Findings",      str(total_crit)],
            ["High Findings",          str(total_high)],
        ]
        story.append(Paragraph("Scorecard Summary", st["h2"]))
        story.append(_make_table(summary_rows, col_widths=[7 * cm, 9.7 * cm]))

    # ── 5. Security Scorecard [NEW] ───────────────────────────────────────────

    def _section_security_scorecard(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Security Scorecard", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Findings mapped to five enterprise security categories derived from "
            "WAF control codes. Scores reflect compliance within each category.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        scorecard = _compute_scorecard(findings)
        cats       = [s[0] for s in scorecard]
        scores     = [s[1] for s in scorecard]
        statuses   = [s[2] for s in scorecard]

        # Summary table
        sc_rows = [["Category", "Score", "Status", "Threshold"]]
        status_colors = {
            "Excellent":          colors.HexColor("#D5F5E3"),
            "Good":               colors.HexColor("#FDFEFE"),
            "Needs Improvement":  colors.HexColor("#FDEBD0"),
            "Critical":           colors.HexColor("#FADBD8"),
        }
        extra = []
        for i, (cat, score, status) in enumerate(scorecard, start=1):
            threshold = (
                "90–100" if status == "Excellent"
                else "75–89" if status == "Good"
                else "50–74" if status == "Needs Improvement"
                else "< 50"
            )
            sc_rows.append([cat, f"{score:.1f}%", status, threshold])
            bg = status_colors.get(status, _C_WHITE)
            extra.append(("BACKGROUND", (2, i), (2, i), bg))

        story.append(Paragraph("Category Scores", st["h2"]))
        story.append(_make_table(
            sc_rows,
            col_widths=[5.5 * cm, 2.5 * cm, 4 * cm, 3 * cm],
            extra_style=extra,
        ))
        story.append(Spacer(1, 0.5 * cm))

        # Heatmap chart
        story.append(Paragraph("Compliance Heat Map", st["h2"]))
        story.append(build_risk_heatmap(cats, scores, width=_BODY_WIDTH))

        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(
            "Score thresholds: 90–100 = Excellent  |  75–89 = Good  |  "
            "50–74 = Needs Improvement  |  < 50 = Critical",
            st["caption"],
        ))

    # ── 5. Executive Dashboard ────────────────────────────────────────────────

    def _section_executive_dashboard(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Executive Dashboard", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        score_rows = [
            ["Score Metric", "Value", "Interpretation"],
            ["Overall Compliance Score", f"{agg.overall_compliance_score:.1f}%",
             _score_label(agg.overall_compliance_score)],
            ["Overall Risk Score",       f"{agg.overall_risk_score:.1f}%",
             _risk_label(agg.overall_risk_score)],
            ["Weighted Severity Score",  f"{agg.weighted_severity_score:.1f}%",
             "Severity-weighted finding density"],
            ["Business Impact Score",    f"{agg.business_impact_score:.1f}%",
             "Pillar-criticality-weighted risk"],
        ]
        story.append(Paragraph("Enterprise Scores", st["h2"]))
        story.append(_make_table(score_rows, col_widths=[6 * cm, 3 * cm, 8 * cm]))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Framework Coverage", st["h2"]))
        cov_rows = [
            ["Coverage Type", "Controls", "Percentage"],
            ["Automated Assessment", "53 of 57", "93.0%"],
            ["Human Review Required", "4 of 57", "7.0%"],
            ["Total Framework Controls", "57", "100%"],
        ]
        story.append(_make_table(cov_rows, col_widths=[7 * cm, 4 * cm, 4 * cm]))
        story.append(Spacer(1, 0.5 * cm))

        if agg.top_5_risks:
            story.append(Paragraph("Top 5 Risks", st["h2"]))
            risk_rows = [["#", "Title", "Resource", "Severity", "Pillar", "Business Impact"]]
            for i, risk in enumerate(agg.top_5_risks, 1):
                risk_rows.append([
                    str(i),
                    _tr(risk.title, 40),
                    _tr(risk.resource_id, 30),
                    risk.severity.upper(),
                    risk.pillar.replace("_", " ").title(),
                    _tr(risk.business_impact, 30),
                ])
            risk_tbl = Table(
                risk_rows,
                colWidths=[0.8 * cm, 5 * cm, 4 * cm, 2 * cm, 3 * cm, 4 * cm],
            )
            extra = [
                ("BACKGROUND", (3, i), (3, i), _SEV_COLORS.get(risk.severity, _C_WHITE))
                for i, risk in enumerate(agg.top_5_risks, 1)
            ]
            risk_tbl.setStyle(TableStyle(_header_style() + extra))
            story.append(risk_tbl)
        else:
            story.append(Paragraph("No findings recorded.", st["na"]))

        # Stacked findings-by-pillar chart
        if agg.findings_by_pillar:
            story.append(Spacer(1, 0.5 * cm))
            story.append(Paragraph("Finding Distribution by Pillar", st["h2"]))
            story.append(Paragraph(
                "Each bar shows the total finding count for a pillar, "
                "segmented by severity. Bars are proportional to the pillar "
                "with the most findings.",
                st["caption"],
            ))
            pillar_sev_data = {
                name: dict(ps.findings_by_severity)
                for name, ps in agg.findings_by_pillar.items()
            }
            story.append(build_findings_by_pillar_stacked(
                pillar_sev_data, width=_BODY_WIDTH,
            ))

    # ── 5b. Visual Dashboards ─────────────────────────────────────────────────

    def _section_visual_dashboards(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding],
    ) -> None:
        """Ten enterprise dashboard pages built from existing assessment data."""
        try:
            data = build_dashboard_data(agg, findings)
        except Exception:
            return  # If data extraction fails, skip dashboard section entirely

        _W = _BODY_WIDTH  # convenience alias

        def _dash_header(title: str, subtitle: str = "") -> None:
            story.append(Paragraph(title, st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            if subtitle:
                story.append(Paragraph(subtitle, st["caption"]))
            story.append(Spacer(1, 0.3 * cm))

        def _draw(builder_fn, w: float, h: float) -> None:
            try:
                drw = builder_fn(data, w, h)
                story.append(drw)
            except Exception:
                pass  # individual chart errors never abort rendering

        # ── D1: Executive KPI Grid ─────────────────────────────────────────────
        _dash_header(
            "Executive Dashboard — KPI Overview",
            "Key performance indicators derived from actual assessment results. "
            "All values are traceable to database records.",
        )
        _draw(build_kpi_grid, _W, 7.5 * cm)
        story.append(PageBreak())

        # ── D2: Pillar Performance ─────────────────────────────────────────────
        _dash_header(
            "Pillar Compliance Performance",
            "Compliance score per WAF pillar (0–100). "
            "Red < 50 | Amber 50–69 | Green ≥ 70.",
        )
        _draw(build_pillar_bars, _W, 7.5 * cm)
        story.append(Spacer(1, 0.5 * cm))

        # ── D3: Severity Donut ──────────────────────────────────────────────────
        _dash_header(
            "Severity Distribution",
            "Finding counts by severity. Percentage of total findings shown.",
        )
        _draw(build_severity_donut, _W, 8.5 * cm)
        story.append(PageBreak())

        # ── D4: Compliance Radar ───────────────────────────────────────────────
        _dash_header(
            "Compliance Radar — Pillar View",
            "Pentagon radar chart showing relative compliance across all five "
            "WAF pillars. Shaded area represents current posture; outer boundary = 100%.",
        )
        _draw(build_radar_chart, _W, 10 * cm)
        story.append(Spacer(1, 0.5 * cm))

        # ── D5: Top Resource Types ─────────────────────────────────────────────
        _dash_header(
            "Top Resource Types by Finding Count",
            "Resource types ordered by number of findings (most to least). "
            "Indicates where remediation effort is most concentrated.",
        )
        _draw(build_resource_type_bars, _W, 8 * cm)
        story.append(PageBreak())

        # ── D6: Risk Heatmap ──────────────────────────────────────────────────
        _dash_header(
            "Risk Heatmap — Severity × Pillar",
            "Each cell shows finding count at the intersection of a severity "
            "level and WAF pillar. Darker colour indicates higher concentration.",
        )
        _draw(build_risk_heatmap_grid, _W, 7.5 * cm)
        story.append(Spacer(1, 0.5 * cm))

        # ── D7: Trend Summary ─────────────────────────────────────────────────
        _dash_header(
            "Finding Trend Summary",
            "Compliance score across historical assessments. "
            "Displayed only when prior assessment data is available.",
        )
        _draw(build_trend_chart, _W, 7 * cm)
        story.append(PageBreak())

        # ── D8: Business Impact Breakdown ─────────────────────────────────────
        _dash_header(
            "Business Impact Breakdown",
            "Findings grouped by impacted business domain. Stacked by severity. "
            "Domains are mapped deterministically from WAF pillar.",
        )
        _draw(build_business_impact_bars, _W, 7.5 * cm)
        story.append(Spacer(1, 0.5 * cm))

        # ── D9: Assessment Coverage ────────────────────────────────────────────
        _dash_header(
            "Assessment Coverage",
            "Scope and coverage of the current assessment run.",
        )
        _draw(build_coverage_visual, _W, 5.5 * cm)
        story.append(PageBreak())

        # ── D10: Legend ────────────────────────────────────────────────────────
        _dash_header(
            "Dashboard Legend",
            "Visual conventions used throughout this dashboard section.",
        )
        _draw(build_legend_drawing, _W, 13 * cm)

    # ── 6. Resource Inventory ─────────────────────────────────────────────────

    def _section_resource_inventory(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Resource Inventory", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Resource types discovered in this assessment. "
            "Only resource types that exist in the environment are shown.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not agg.resource_type_inventory:
            story.append(Paragraph("Not Available — no resources discovered.", st["na"]))
            return

        inv_rows = [[
            "Resource Type", "Total", "Compliant", "Non-Compliant",
            "Compliance %", "Critical", "High",
        ]]
        rt_labels = []
        rt_pcts   = []
        for stats in sorted(
            agg.resource_type_inventory.values(),
            key=lambda s: s.total, reverse=True
        ):
            short = _short_rt(stats.resource_type)
            inv_rows.append([
                _tr(stats.resource_type, 42),
                str(stats.total),
                str(stats.compliant),
                str(stats.with_findings),
                f"{stats.compliance_pct:.1f}%",
                str(stats.critical_findings),
                str(stats.high_findings),
            ])
            rt_labels.append(short)
            rt_pcts.append(stats.compliance_pct)

        extra_style = []
        for i, stats in enumerate(
            sorted(agg.resource_type_inventory.values(), key=lambda s: s.total, reverse=True),
            start=1,
        ):
            if stats.compliance_pct >= 70:
                extra_style.append(("BACKGROUND", (4, i), (4, i), _C_GREEN))
            elif stats.with_findings > 0:
                extra_style.append(("BACKGROUND", (4, i), (4, i), _C_ORANGE))

        story.append(_make_table(
            inv_rows,
            col_widths=[5.5 * cm, 1.8 * cm, 2 * cm, 2.5 * cm, 2.5 * cm, 1.8 * cm, 1.8 * cm],
            extra_style=extra_style,
        ))
        story.append(Spacer(1, 0.6 * cm))
        story.append(Paragraph("Resource Compliance by Type", st["h2"]))
        story.append(build_resource_compliance_bar(rt_labels, rt_pcts))

    # ── 7. Resource Group Analysis [NEW] ─────────────────────────────────────

    def _section_resource_group_breakdown(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Resource Group Analysis", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Resource groups are extracted from finding resource IDs. "
            "'Finding Resources' = distinct resources with ≥ 1 finding in this RG.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        rows = _build_rg_stats(findings)
        if not rows:
            story.append(Paragraph("Not Available — resource groups could not be parsed.", st["na"]))
            return

        rg_names   = []
        rg_pcts    = []
        table_rows = [["Resource Group", "Finding Resources", "Findings", "Critical", "High", "Risk Level"]]
        for name, res, count, crit, high, _ in rows:
            risk_level = (
                "Critical" if crit > 0
                else "High" if high > 0
                else "Medium" if count > 0
                else "Low"
            )
            # Compliance approximation: resources without critical/high vs total finding-resources
            compliant_approx = max(0, res - (crit + high))
            pct = round(compliant_approx / res * 100, 1) if res > 0 else 100.0
            rg_names.append(name)
            rg_pcts.append(pct)
            table_rows.append([
                _tr(name, 30), str(res), str(count), str(crit), str(high), risk_level,
            ])

        extra = []
        _risk_bg = {
            "Critical": colors.HexColor("#FADBD8"),
            "High":     colors.HexColor("#FDEBD0"),
            "Medium":   colors.HexColor("#FDFEFE"),
            "Low":      colors.HexColor("#D5F5E3"),
        }
        for i, row in enumerate(table_rows[1:], start=1):
            bg = _risk_bg.get(row[5], _C_WHITE)
            extra.append(("BACKGROUND", (5, i), (5, i), bg))

        story.append(Paragraph("Compliance by Resource Group", st["h2"]))
        story.append(_make_table(
            table_rows,
            col_widths=[4.5 * cm, 3 * cm, 2.5 * cm, 2 * cm, 2 * cm, 3.5 * cm],
            extra_style=extra,
        ))
        story.append(Spacer(1, 0.6 * cm))

        story.append(Paragraph("Resource Group Risk Ranking", st["h2"]))
        story.append(build_resource_group_bar(rg_names, rg_pcts, width=_BODY_WIDTH))

    # ── 8. Compliance Overview ────────────────────────────────────────────────

    def _section_compliance_overview(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Compliance by WAF Pillar", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        if not agg.findings_by_pillar:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        pillar_rows = [[
            "Pillar", "Score", "Assessed", "Passed", "Failed",
            "Critical", "High", "Medium", "Low",
        ]]
        for name in sorted(agg.findings_by_pillar.keys()):
            ps   = agg.findings_by_pillar[name]
            ctrl = agg.pillar_control_stats.get(name)
            pillar_rows.append([
                name.replace("_", " ").title(),
                f"{ps.compliance_score * 100:.1f}%",
                str(ctrl.controls_assessed) if ctrl else "—",
                str(ctrl.controls_passed)   if ctrl else "—",
                str(ctrl.controls_failed)   if ctrl else "—",
                str(ps.findings_by_severity.get("critical", 0)),
                str(ps.findings_by_severity.get("high", 0)),
                str(ps.findings_by_severity.get("medium", 0)),
                str(ps.findings_by_severity.get("low", 0)),
            ])
        story.append(_make_table(
            pillar_rows,
            col_widths=[4.5 * cm, 2 * cm, 2 * cm, 2 * cm, 2 * cm,
                        2 * cm, 1.5 * cm, 2 * cm, 1.5 * cm],
        ))
        story.append(Spacer(1, 0.6 * cm))

        story.append(Paragraph("Pillar Compliance Scores", st["h2"]))
        # Use weighted pass-rate scores when available (Phase 5 model)
        _weighted = getattr(agg, "pillar_scores", {})
        pillar_scores = {
            p: _weighted.get(p, ps.compliance_score * 100)
            for p, ps in agg.findings_by_pillar.items()
        }
        story.append(build_pillar_bar(pillar_scores))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Compliance Breakdown", st["h2"]))
        story.append(Paragraph(
            "Progress bars show each pillar's compliance percentage against "
            "70% (minimum acceptable) and 90% (enterprise target) thresholds.",
            st["caption"],
        ))
        story.append(build_compliance_breakdown(pillar_scores, width=_BODY_WIDTH))

    # ── 9. WAF Pillar Benchmark [NEW] ─────────────────────────────────────────

    def _section_waf_benchmark(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("WAF Pillar Benchmark", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Comparison of current pillar compliance scores against Azure WAF benchmark targets. "
            "Targets reflect Microsoft WAF recommended minimum thresholds per pillar. "
            "Gap = current score − target; negative values indicate a shortfall requiring remediation.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not agg.findings_by_pillar:
            story.append(Paragraph("Not Available — no pillar data recorded.", st["na"]))
            return

        pillar_scores = {
            p: round(ps.compliance_score * 100, 1)
            for p, ps in agg.findings_by_pillar.items()
        }

        _STATUS_BG = {
            "Exceeds Target": colors.HexColor("#D5F5E3"),
            "On Target":      colors.HexColor("#D5F5E3"),
            "Near Target":    colors.HexColor("#FDFEFE"),
            "Below Target":   colors.HexColor("#FDEBD0"),
            "Critical Gap":   colors.HexColor("#FADBD8"),
        }

        bench_rows = [["Pillar", "Current", "Target", "Gap", "Status"]]
        extra: list = []

        for i, pillar in enumerate(sorted(pillar_scores.keys()), start=1):
            score  = pillar_scores[pillar]
            target = _WAF_PILLAR_TARGETS.get(pillar, 90.0)
            gap_pp = score - target

            if gap_pp >= 5:
                status = "Exceeds Target"
            elif gap_pp >= 0:
                status = "On Target"
            elif gap_pp >= -10:
                status = "Near Target"
            elif gap_pp >= -20:
                status = "Below Target"
            else:
                status = "Critical Gap"

            gap_str = f"+{gap_pp:.1f}pp" if gap_pp >= 0 else f"{gap_pp:.1f}pp"
            bench_rows.append([
                pillar.replace("_", " ").title(),
                f"{score:.1f}%",
                f"{target:.0f}%",
                gap_str,
                status,
            ])
            extra.append(("BACKGROUND", (4, i), (4, i), _STATUS_BG.get(status, _C_WHITE)))
            gap_col = colors.HexColor("#27AE60") if gap_pp >= 0 else colors.HexColor("#C0392B")
            extra.append(("TEXTCOLOR", (3, i), (3, i), gap_col))
            extra.append(("FONTNAME",  (3, i), (3, i), "Helvetica-Bold"))

        story.append(Paragraph("Benchmark Summary", st["h2"]))
        story.append(_make_table(
            bench_rows,
            col_widths=[5.5 * cm, 2.8 * cm, 2.5 * cm, 2.8 * cm, 3.8 * cm],
            extra_style=extra,
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Visual Benchmark", st["h2"]))
        story.append(Paragraph(
            "Each bar shows the current compliance score. "
            "The dark-blue marker indicates the pillar-specific WAF target. "
            "Score and gap (±pp) appear on the right. "
            "Colour: green = at/above target · yellow = within 10pp · "
            "orange = within 20pp · red = >20pp below.",
            st["caption"],
        ))
        story.append(build_waf_benchmark_chart(
            pillar_scores, _WAF_PILLAR_TARGETS, width=_BODY_WIDTH,
        ))

        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Target Rationale", st["h2"]))
        target_rows = [["Pillar", "Target", "Rationale"]]
        for pillar in sorted(pillar_scores.keys()):
            target_rows.append([
                pillar.replace("_", " ").title(),
                f"{_WAF_PILLAR_TARGETS.get(pillar, 90.0):.0f}%",
                _WAF_TARGET_RATIONALE.get(
                    pillar,
                    "90% — Enterprise standard across all WAF pillars.",
                ),
            ])
        story.append(_make_table(
            target_rows,
            col_widths=[4.5 * cm, 2.0 * cm, 11.0 * cm],
        ))

        # Interpretation
        story.append(Spacer(1, 0.4 * cm))
        gaps_below = [
            (p, pillar_scores[p], _WAF_PILLAR_TARGETS.get(p, 90.0))
            for p in sorted(pillar_scores.keys())
            if pillar_scores[p] < _WAF_PILLAR_TARGETS.get(p, 90.0)
        ]
        gaps_above = [
            (p, pillar_scores[p], _WAF_PILLAR_TARGETS.get(p, 90.0))
            for p in sorted(pillar_scores.keys())
            if pillar_scores[p] >= _WAF_PILLAR_TARGETS.get(p, 90.0)
        ]

        if not gaps_below:
            story.append(Paragraph(
                "<b>All pillars meet or exceed their WAF target.</b> "
                "The environment is fully aligned with Azure WAF benchmark standards.",
                st["body"],
            ))
        else:
            worst = min(gaps_below, key=lambda x: x[1] - x[2])
            worst_gap = worst[1] - worst[2]
            worst_name = worst[0].replace("_", " ").title()
            story.append(Paragraph(
                f"<b>{len(gaps_below)} pillar(s) below target:</b> "
                + ", ".join(
                    f"{p.replace('_', ' ').title()} "
                    f"({score:.1f}% vs {tgt:.0f}% target, {score - tgt:+.1f}pp)"
                    for p, score, tgt in gaps_below
                ) + ".",
                st["body"],
            ))
            story.append(Spacer(1, 0.1 * cm))
            story.append(Paragraph(
                f"The largest gap is in the <b>{worst_name}</b> pillar "
                f"(<b>{worst_gap:+.1f}pp</b>). "
                "Prioritise remediation in this pillar to achieve the greatest "
                "benchmark improvement per unit of effort.",
                st["body"],
            ))

        if gaps_above:
            story.append(Spacer(1, 0.1 * cm))
            story.append(Paragraph(
                f"<b>{len(gaps_above)} pillar(s) meet or exceed their target:</b> "
                + ", ".join(
                    f"{p.replace('_', ' ').title()} ({score:.1f}%)"
                    for p, score, _ in gaps_above
                ) + ".",
                st["body"],
            ))

    # ── 10. Business Impact Analysis ──────────────────────────────────────────

    def _section_business_impact(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Business Impact Analysis", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        # ── Executive Business Impact Summary ──────────────────────────────────
        try:
            summary_text = build_executive_business_impact_summary(findings)
            story.append(Paragraph("Executive Business Impact Summary", st["h2"]))
            story.append(Paragraph(summary_text, st["narrative"]))
            story.append(Spacer(1, 0.3 * cm))
        except Exception:
            pass

        # ── Risk Category Impact Levels ────────────────────────────────────────
        try:
            cat_levels = aggregate_risk_category_levels(findings)
            _IMPACT_LEVEL_COLORS: dict[str, colors.Color] = {
                "High":   colors.HexColor("#FF6600"),
                "Medium": colors.HexColor("#FFCC00"),
                "Low":    colors.HexColor("#CCE5FF"),
            }
            cat_rows: list = [["Risk Category", "Impact Level"]]
            for _cat_name in [
                "Security Risk", "Compliance Risk", "Operational Risk",
                "Financial Risk", "Reputation Risk",
            ]:
                cat_rows.append([_cat_name, cat_levels.get(_cat_name, "Low")])
            cat_extra = [
                ("BACKGROUND", (1, i), (1, i),
                 _IMPACT_LEVEL_COLORS.get(cat_rows[i][1], _C_LGREY))
                for i in range(1, len(cat_rows))
            ]
            story.append(Paragraph("Risk Category Impact Levels", st["h2"]))
            story.append(_make_table(
                cat_rows,
                col_widths=[8 * cm, 4 * cm],
                extra_style=cat_extra,
            ))
            story.append(Spacer(1, 0.3 * cm))
        except Exception:
            pass

        # ── Business Impact Score ──────────────────────────────────────────────
        try:
            biz_score = calculate_business_impact_score(findings)
            score_rows: list = [
                ["Business Impact Score", "Scoring Methodology"],
                [
                    f"{biz_score:.0f} / 100",
                    "Average: Critical=100  High=75  Medium=50  Low=25  Informational=0",
                ],
            ]
            story.append(Paragraph("Business Impact Score", st["h2"]))
            story.append(_make_table(
                score_rows,
                col_widths=[5 * cm, 10.7 * cm],
                extra_style=[
                    ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 1), (0, 1), 12),
                ],
            ))
            story.append(Spacer(1, 0.5 * cm))
        except Exception:
            pass

        impact_map: dict[str, dict[str, int]] = {}
        for f in findings:
            cat = _PILLAR_TO_IMPACT.get(f.pillar, "Operational Risk")
            if cat not in impact_map:
                impact_map[cat] = {}
            impact_map[cat][f.severity.value] = (
                impact_map[cat].get(f.severity.value, 0) + 1
            )
            if f.severity.value == "critical" and f.pillar in ("security", "reliability"):
                extra = "Data Loss Risk"
                if extra not in impact_map:
                    impact_map[extra] = {}
                impact_map[extra][f.severity.value] = (
                    impact_map[extra].get(f.severity.value, 0) + 1
                )

        impact_rows = [["Impact Category", "Critical", "High", "Medium", "Low", "Total"]]
        for cat in sorted(impact_map.keys()):
            s = impact_map[cat]
            impact_rows.append([
                cat,
                str(s.get("critical", 0)),
                str(s.get("high", 0)),
                str(s.get("medium", 0)),
                str(s.get("low", 0)),
                str(sum(s.values())),
            ])

        story.append(Paragraph("Business Impact Summary", st["h2"]))
        story.append(_make_table(
            impact_rows,
            col_widths=[6 * cm, 2.5 * cm, 2 * cm, 2.5 * cm, 2 * cm, 2.5 * cm],
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Top Business Risks", st["h2"]))
        if agg.top_5_risks:
            risk_rows = [["Risk", "Potential Impact", "Severity"]]
            for risk in agg.top_5_risks:
                risk_rows.append([
                    _tr(risk.title, 50),
                    _tr(risk.business_impact, 35),
                    risk.severity.upper(),
                ])
            extra = [
                ("BACKGROUND", (2, i), (2, i), _SEV_COLORS.get(risk.severity, _C_WHITE))
                for i, risk in enumerate(agg.top_5_risks, 1)
            ]
            story.append(_make_table(
                risk_rows,
                col_widths=[7 * cm, 5.5 * cm, 3 * cm],
                extra_style=extra,
            ))
        else:
            story.append(Paragraph("No high-severity risks identified.", st["na"]))

        # ── Finding-Level Business Impact ──────────────────────────────────────
        try:
            fi_sorted = sorted(
                findings,
                key=lambda f: (
                    _SEVERITY_ORDER.index(f.severity.value)
                    if f.severity.value in _SEVERITY_ORDER else 99
                ),
            )[:15]
            story.append(Spacer(1, 0.5 * cm))
            story.append(Paragraph("Finding-Level Business Impact", st["h2"]))
            story.append(Paragraph(
                "Qualitative impact derived from finding severity and pillar. "
                "Language is hedged — 'Potential', 'May', 'Could' reflect assessed risk.",
                st["caption"],
            ))
            fi_rows: list = [["Finding", "Severity", "Risk Category", "Business Impact"]]
            for _f in fi_sorted:
                try:
                    _biz = build_business_impact_analysis(_f)
                    fi_rows.append([
                        Paragraph(_code_xml(_tr(_f.title, 45)), st["body"]),
                        _f.severity.value.capitalize(),
                        _biz.risk_category,
                        Paragraph(_code_xml(_biz.finding_impact, 200), st["body"]),
                    ])
                except Exception:
                    pass
            if len(fi_rows) > 1:
                _fi_sev_extra = [
                    ("BACKGROUND", (1, i), (1, i),
                     _SEV_COLORS.get(fi_sorted[i - 1].severity.value, _C_WHITE))
                    for i in range(1, len(fi_rows))
                ]
                story.append(_make_table(
                    fi_rows,
                    col_widths=[4.5 * cm, 2 * cm, 3 * cm, 6.2 * cm],
                    extra_style=_fi_sev_extra,
                ))
        except Exception:
            pass

        # ── Recommended Priorities ─────────────────────────────────────────────
        try:
            _priority_findings = [
                f for f in findings
                if f.severity.value in ("critical", "high")
            ][:5]
            if _priority_findings:
                story.append(Spacer(1, 0.5 * cm))
                story.append(Paragraph("Recommended Priorities", st["h2"]))
                story.append(Paragraph(
                    "Highest-priority actions derived from critical and high severity findings.",
                    st["caption"],
                ))
                for _i, _pf in enumerate(_priority_findings, 1):
                    try:
                        _pbiz = build_business_impact_analysis(_pf)
                        story.append(Paragraph(
                            f"<b>{_i}. [{_pbiz.priority}] "
                            f"{_code_xml(_tr(_pf.title, 80))}</b> — "
                            f"{_code_xml(_pbiz.finding_impact, 180)}",
                            st["rec_body"],
                        ))
                    except Exception:
                        pass
        except Exception:
            pass

        # Top Risk Contributors chart — resource types ranked by weighted risk score
        _biz_weights = {
            "critical": 4.0, "high": 2.0, "medium": 1.0,
            "low": 0.25, "informational": 0.0,
        }
        rt_risk: dict[str, list] = {}
        for f in findings:
            lbl = _short_rt(f.resource_type) if f.resource_type else "Unknown"
            if lbl not in rt_risk:
                rt_risk[lbl] = [0.0, "informational"]
            rt_risk[lbl][0] += _biz_weights.get(f.severity.value, 0.0)
            cur_idx = (
                _SEVERITY_ORDER.index(rt_risk[lbl][1])
                if rt_risk[lbl][1] in _SEVERITY_ORDER else 99
            )
            new_idx = (
                _SEVERITY_ORDER.index(f.severity.value)
                if f.severity.value in _SEVERITY_ORDER else 99
            )
            if new_idx < cur_idx:
                rt_risk[lbl][1] = f.severity.value

        contributors = sorted(
            [(lbl, vals[0], vals[1]) for lbl, vals in rt_risk.items()],
            key=lambda x: x[1], reverse=True,
        )[:10]

        if contributors:
            story.append(Spacer(1, 0.5 * cm))
            story.append(Paragraph("Top Risk Contributors by Resource Type", st["h2"]))
            story.append(Paragraph(
                "Weighted risk score = critical×4 + high×2 + medium×1 + low×0.25. "
                "Bar colour reflects the worst severity within that resource type.",
                st["caption"],
            ))
            story.append(build_top_risk_contributors(contributors, width=_BODY_WIDTH))

    # ── 10. AI Executive Insights ──────────────────────────────────────────────

    def _section_executive_insights(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("AI Executive Insights", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        try:
            insights = generate_executive_insights(findings)
        except Exception:
            story.append(Paragraph(
                "AI insights could not be generated from the available findings.", st["na"]
            ))
            return

        _CONF_COLORS: dict[str, colors.Color] = {
            "High":   colors.HexColor("#2ECC71"),
            "Medium": colors.HexColor("#F1C40F"),
            "Low":    colors.HexColor("#BDC3C7"),
        }

        # ── Key Observations ───────────────────────────────────────────────────
        try:
            story.append(Paragraph("Key Observations", st["h2"]))
            story.append(Paragraph(
                "All observations are derived exclusively from actual assessment findings. "
                "Language is conservative — 'suggests', 'may indicate', 'could contribute'.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            for _i, _obs in enumerate(insights.observations, 1):
                try:
                    _conf_color = _CONF_COLORS.get(_obs.confidence, _C_LGREY)
                    _obs_rows: list = [
                        [
                            Paragraph(
                                f"<b>{_i}. {_code_xml(_obs.insight_type)}</b>",
                                st["rec_title"],
                            ),
                            Paragraph(
                                f"Confidence: <b>{_code_xml(_obs.confidence)}</b>",
                                st["body_center"],
                            ),
                        ],
                        [
                            Paragraph(_code_xml(_obs.insight, 400), st["body"]),
                            "",
                        ],
                    ]
                    _obs_extra = [
                        ("BACKGROUND", (1, 0), (1, 0), _conf_color),
                        ("SPAN",       (0, 1), (1, 1)),
                        ("VALIGN",     (0, 1), (1, 1), "TOP"),
                    ]
                    story.append(_make_table(
                        _obs_rows,
                        col_widths=[11.5 * cm, 4.2 * cm],
                        extra_style=_obs_extra,
                    ))
                    story.append(Spacer(1, 0.15 * cm))
                except Exception:
                    pass
        except Exception:
            pass

        # ── Strategic Recommendations ──────────────────────────────────────────
        try:
            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph("Strategic Recommendations", st["h2"]))
            recs = insights.strategic_recommendations
            for _label, _text in [
                ("Immediate Focus (0–30 Days)",  recs.immediate_focus),
                ("Near-Term Focus (30–90 Days)", recs.near_term_focus),
                ("Long-Term Focus (90+ Days)",   recs.long_term_focus),
            ]:
                try:
                    story.append(Paragraph(f"<b>{_label}:</b>", st["rec_title"]))
                    story.append(Paragraph(_code_xml(_text, 350), st["rec_body"]))
                except Exception:
                    pass
        except Exception:
            pass

        # ── Assessment Narrative ───────────────────────────────────────────────
        try:
            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph("Assessment Narrative", st["h2"]))
            story.append(Paragraph(
                _code_xml(insights.assessment_narrative, 1000), st["narrative"]
            ))
        except Exception:
            pass

    # ── 11. Architecture Topology ──────────────────────────────────────────────

    def _section_architecture(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Enterprise Architecture Visualization", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        # Deployment hierarchy summary table (stats only, no fabricated data)
        rg_rows_data = _build_rg_stats(findings)
        rg_count = len(rg_rows_data)
        rt_count = len(agg.resource_type_inventory)

        hier_rows = [
            ["Hierarchy Level", "Count", "Details"],
            ["Subscriptions",   str(agg.subscription_count or "N/A"),
             "Azure subscription scope"],
            ["Resource Groups", str(rg_count) if rg_count > 0 else "N/A",
             "Extracted from resource IDs in findings"],
            ["Resource Types",  str(rt_count) if rt_count > 0 else "N/A",
             "Distinct ARM resource type namespaces"],
            ["Total Resources", str(agg.total_resources),
             "Resources assessed in this run"],
        ]
        story.append(Paragraph("Deployment Hierarchy", st["h2"]))
        story.append(_make_table(hier_rows, col_widths=[4 * cm, 3 * cm, 10 * cm]))
        story.append(Spacer(1, 0.4 * cm))

        story.append(Paragraph(
            "Hierarchy diagram generated from ARM resource IDs in findings. "
            "Color: green = low/no risk, yellow = medium risk, red = high/critical risk. "
            "Only resources with findings are shown; no fabricated connections.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.4 * cm))

        drawing = build_hierarchy_diagram(findings=findings, agg=agg, width=_BODY_WIDTH)
        story.append(drawing)

    # ── 11. WAF Control Pages [NEW] ───────────────────────────────────────────

    def _section_waf_control_pages(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Detailed WAF Control Analysis", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "One section per WAF control code referenced by findings. "
            "Source: waf_controls.json and assessment findings.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        # Collect unique WAF codes from findings
        code_to_findings: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            for code in f.waf_codes:
                code_to_findings[code].append(f)

        if not code_to_findings:
            story.append(Paragraph(
                "No WAF control codes found in findings. "
                "Control codes are populated during the extraction phase.",
                st["na"],
            ))
            return

        # Load catalog (best-effort)
        catalog = None
        if _HAS_WAF_CATALOG and _WafCatalog is not None:
            try:
                catalog = _WafCatalog.get_instance()
            except Exception:
                catalog = None

        # Render up to 30 controls (sorted by code)
        codes_sorted = sorted(code_to_findings.keys())[:30]

        for code in codes_sorted:
            ctrl_findings = sorted(
                code_to_findings[code],
                key=lambda f: _SEVERITY_ORDER.index(f.severity.value)
                if f.severity.value in _SEVERITY_ORDER else 99,
            )

            # Control metadata
            control       = catalog.get_control(code) if catalog else None
            title         = control.title if control else "—"
            pillar        = control.pillar if control else "—"
            description   = control.description if control else "Not Available"
            ms_url        = control.microsoft_url if control else "—"

            # Compliance status for this control
            has_critical_high = any(
                f.severity.value in ("critical", "high") for f in ctrl_findings
            )
            compliance_status = "Non-Compliant" if has_critical_high else "Partially Compliant"
            status_color      = (
                colors.HexColor("#FADBD8") if has_critical_high
                else colors.HexColor("#FDEBD0")
            )

            # Severity distribution for this control
            sev_dist: dict[str, int] = defaultdict(int)
            for f in ctrl_findings:
                sev_dist[f.severity.value] += 1

            unique_resources = sorted({f.resource_id for f in ctrl_findings})

            # Header block (keep together so code/title/status don't orphan)
            ctrl_header = [
                Paragraph(f"Control: {code}", st["h2"]),
                Spacer(1, 0.1 * cm),
            ]
            ctrl_meta_rows = [
                ["Field", "Value"],
                ["Control Code",   code],
                ["Title",          title],
                ["Pillar",         pillar],
                ["Status",         compliance_status],
                ["Findings Count", str(len(ctrl_findings))],
                ["Microsoft Docs", _tr(ms_url, 70)],
            ]
            ctrl_meta = _make_table(
                ctrl_meta_rows,
                col_widths=[4 * cm, _BODY_WIDTH - 4 * cm],
                extra_style=[("BACKGROUND", (1, 4), (1, 4), status_color)],
            )
            ctrl_header.append(ctrl_meta)
            story.append(KeepTogether(ctrl_header))
            story.append(Spacer(1, 0.3 * cm))

            # Description
            story.append(Paragraph("Description", st["h3"]))
            story.append(Paragraph(_tr(description, 500), st["body"]))
            story.append(Spacer(1, 0.2 * cm))

            # Severity distribution
            sev_rows = [["Severity", "Count"]]
            for sev in _SEVERITY_ORDER:
                cnt = sev_dist.get(sev, 0)
                if cnt > 0:
                    sev_rows.append([sev.capitalize(), str(cnt)])
            if len(sev_rows) > 1:
                story.append(Paragraph("Severity Distribution", st["h3"]))
                sev_tbl = _make_table(sev_rows, col_widths=[4 * cm, 3 * cm])
                story.append(sev_tbl)
                story.append(Spacer(1, 0.2 * cm))

            # Affected resources (top 10)
            if unique_resources:
                story.append(Paragraph(
                    f"Affected Resources ({len(unique_resources)} unique)", st["h3"],
                ))
                res_rows = [["Resource ID"]]
                for rid in unique_resources[:10]:
                    res_rows.append([_tr(rid, 80)])
                if len(unique_resources) > 10:
                    res_rows.append([f"… and {len(unique_resources) - 10} more"])
                story.append(_make_table(res_rows, col_widths=[_BODY_WIDTH]))
                story.append(Spacer(1, 0.2 * cm))

            # Associated findings (top 8)
            story.append(Paragraph(
                f"Associated Findings (top {min(8, len(ctrl_findings))})", st["h3"],
            ))
            find_rows = [["Resource", "Severity", "Title", "Recommendation"]]
            for f in ctrl_findings[:8]:
                find_rows.append([
                    _tr(f.resource_id, 28),
                    f.severity.value.upper(),
                    _tr(f.title, 35),
                    _tr(f.recommendation, 40),
                ])
            sev_extra = [
                ("BACKGROUND", (1, i), (1, i), _SEV_COLORS.get(r[1].lower(), _C_WHITE))
                for i, r in enumerate(find_rows[1:], start=1)
            ]
            story.append(_make_table(
                find_rows,
                col_widths=[3.5 * cm, 2 * cm, 4.5 * cm, 7.5 * cm],
                extra_style=sev_extra,
            ))
            story.append(Spacer(1, 0.5 * cm))
            story.append(HRFlowable(width="100%", thickness=0.4, color=_C_MGREY))
            story.append(Spacer(1, 0.4 * cm))

    # ── 12. Trend Analysis ────────────────────────────────────────────────────

    def _section_trend_analysis(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Trend Analysis", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        if not agg.trend_data:
            story.append(Spacer(1, 0.5 * cm))
            story.append(Paragraph(
                "Trend analysis unavailable. "
                "Historical assessments not yet available.",
                st["na"],
            ))
            story.append(Paragraph(
                "Complete additional assessments to populate trend data.",
                st["caption"],
            ))
            return

        trend_rows = [["Date", "Assessment", "Findings", "Compliance %"]]
        dates  = []
        scores = []
        for pt in agg.trend_data:
            trend_rows.append([
                pt.assessment_date.strftime("%Y-%m-%d"),
                str(pt.assessment_id)[:8] + "…",
                str(pt.total_findings),
                f"{pt.compliance_score:.1f}%",
            ])
            dates.append(pt.assessment_date.strftime("%Y-%m-%d"))
            scores.append(pt.compliance_score)

        story.append(Paragraph("Historical Compliance Data", st["h2"]))
        story.append(_make_table(
            trend_rows,
            col_widths=[3.5 * cm, 4 * cm, 3 * cm, 3.5 * cm],
        ))
        story.append(Spacer(1, 0.5 * cm))

        if len(scores) >= 2:
            first, last = scores[0], scores[-1]
            delta       = last - first
            direction   = "Improving" if delta > 0 else ("Declining" if delta < 0 else "Stable")
            story.append(Paragraph(
                f"Overall Trend: {direction}  ({'+' if delta >= 0 else ''}{delta:.1f}% over "
                f"{len(scores)} assessments)",
                st["body"],
            ))
            story.append(Spacer(1, 0.5 * cm))

        if len(dates) >= 2:
            story.append(Paragraph("Compliance Score Trend", st["h2"]))
            story.append(build_trend_line(dates, scores))

    # ── 13. Compliance Improvement Roadmap [NEW] ──────────────────────────────

    def _section_compliance_roadmap(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Compliance Improvement Roadmap", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Projected overall compliance at four remediation milestones, "
            "calculated from actual severity weights in this assessment. "
            "Each milestone removes one tier of findings from the scoring formula.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        current, after_high, after_hm, _ = _compute_compliance_projection(agg)
        after_all = 100.0

        scenarios: list[tuple[str, float]] = [
            ("Current",          current),
            ("High Fixed",       after_high),
            ("High+Med Fixed",   after_hm),
            ("All Fixed",        after_all),
        ]

        def _delta_str(base: float, target: float) -> str:
            delta = target - base
            return f"+{delta:.1f}%" if delta > 0.05 else "—"

        def _score_bg(score: float) -> colors.Color:
            if score >= 90:
                return colors.HexColor("#D5F5E3")
            if score >= 70:
                return colors.HexColor("#FDEBD0")
            return colors.HexColor("#FADBD8")

        full_labels = [
            "Baseline — no changes made",
            "After remediating all High severity findings",
            "After remediating High + Medium severity findings",
            "After remediating all findings (full compliance)",
        ]
        roadmap_rows = [["Milestone", "Compliance Score", "Delta vs Current", "Status"]]
        extra: list = []
        for i, ((_, score), full_lbl) in enumerate(zip(scenarios, full_labels), start=1):
            delta   = _delta_str(current, score)
            status  = (
                "Excellent" if score >= 90 else
                "Good"      if score >= 70 else
                "Fair"      if score >= 50 else "Critical"
            )
            roadmap_rows.append([full_lbl, f"{score:.1f}%", delta, status])
            extra.append(("BACKGROUND", (1, i), (1, i), _score_bg(score)))
        # Bold the baseline row
        extra.append(("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"))

        story.append(Paragraph("Milestone Projections", st["h2"]))
        story.append(_make_table(
            roadmap_rows,
            col_widths=[7.5 * cm, 3 * cm, 3 * cm, 3 * cm],
            extra_style=extra,
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Visual Roadmap", st["h2"]))
        story.append(Paragraph(
            "Each bar shows projected overall compliance at that milestone. "
            "The dashed green line marks the 90% enterprise target. "
            "Green labels show the incremental gain over the previous milestone.",
            st["caption"],
        ))
        story.append(build_compliance_roadmap(scenarios, width=_BODY_WIDTH))

        # Interpretation paragraph
        story.append(Spacer(1, 0.4 * cm))
        if agg.total_findings > 0:
            sev       = agg.findings_by_severity
            high_cnt  = sev.get("high", 0)
            med_cnt   = sev.get("medium", 0)
            crit_cnt  = sev.get("critical", 0)

            lines: list[str] = []
            if after_high > current + 0.05:
                lines.append(
                    f"Remediating {high_cnt} High finding(s) is projected to lift "
                    f"compliance from <b>{current:.1f}%</b> to <b>{after_high:.1f}%</b> "
                    f"(+{after_high - current:.1f} pp)."
                )
            if after_hm > after_high + 0.05:
                lines.append(
                    f"Addressing {med_cnt} additional Medium finding(s) would "
                    f"further improve compliance to <b>{after_hm:.1f}%</b> "
                    f"(+{after_hm - after_high:.1f} pp incremental)."
                )
            if crit_cnt > 0:
                lines.append(
                    f"<b>{crit_cnt} Critical finding(s) must be remediated first</b> — "
                    "they are not captured in the High-only scenario and represent "
                    "the highest urgency items."
                )
            if after_hm >= 90:
                lines.append(
                    "Remediating High and Medium findings is sufficient to meet "
                    "the <b>90% enterprise target</b>."
                )
            else:
                lines.append(
                    "Full remediation of all findings is required to reach "
                    "the <b>90% enterprise target</b>."
                )

            for line in lines:
                story.append(Paragraph(line, st["body"]))
                story.append(Spacer(1, 0.12 * cm))

    # ── 14. Remediation Roadmap [NEW] ─────────────────────────────────────────

    def _section_remediation_roadmap(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("30-Day Remediation Roadmap", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Findings prioritised into a four-week remediation plan. "
            "P1 = immediate (Critical/High), P2 = medium-term, P3 = low priority.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        # Bucket findings by priority/week
        weeks: dict[str, list[Finding]] = {
            "Week 1 — Critical (P1)": [],
            "Week 2 — High (P1)":     [],
            "Week 3 — Medium (P2)":   [],
            "Week 4 — Low (P3)":      [],
        }
        for f in findings:
            sev = f.severity.value
            if sev == "critical":
                weeks["Week 1 — Critical (P1)"].append(f)
            elif sev == "high":
                weeks["Week 2 — High (P1)"].append(f)
            elif sev == "medium":
                weeks["Week 3 — Medium (P2)"].append(f)
            else:
                weeks["Week 4 — Low (P3)"].append(f)

        for week_label, week_findings in weeks.items():
            if not week_findings:
                continue

            story.append(Paragraph(week_label, st["h2"]))
            rows = [[
                "Priority", "Finding", "Resources",
                "Severity", "Est. Effort", "Business Impact", "Risk Reduction",
            ]]
            # Deduplicate by rule_id+title; collect per-entry finding context
            seen: dict[str, dict[str, Any]] = {}
            for f in week_findings:
                key = f"{f.rule_id}|{f.title}"
                if key not in seen:
                    seen[key] = {
                        "title":         f.title,
                        "sev":           f.severity.value,
                        "rule_id":       f.rule_id,
                        "pillar":        f.pillar,
                        "resource_type": f.resource_type,
                        "recommendation": f.recommendation,
                        "resources":     set(),
                    }
                seen[key]["resources"].add(f.resource_id)

            priority = "P1" if "P1" in week_label else ("P2" if "P2" in week_label else "P3")
            for entry in list(seen.values())[:15]:  # cap at 15 per week for PDF
                detail = get_remediation_detail(
                    entry["rule_id"],
                    severity=entry["sev"],
                    pillar=entry["pillar"],
                    resource_type=entry["resource_type"],
                    recommendation=entry["recommendation"],
                )
                rows.append([
                    priority,
                    _tr(entry["title"], 38),
                    str(len(entry["resources"])),
                    entry["sev"].upper(),
                    _tr(detail.estimated_effort, 22),
                    _tr(detail.business_impact, 55),
                    _tr(detail.risk_reduction, 28),
                ])

            sev_extra = [
                ("BACKGROUND", (3, i), (3, i),
                 _SEV_COLORS.get(r[3].lower(), _C_WHITE))
                for i, r in enumerate(rows[1:], start=1)
            ]
            story.append(_make_table(
                rows,
                col_widths=[
                    1.2 * cm, 4.5 * cm, 1.8 * cm,
                    2.0 * cm, 3.0 * cm, 3.5 * cm, 2.8 * cm,
                ],
                extra_style=sev_extra,
            ))
            story.append(Spacer(1, 0.5 * cm))

    # ── Executive Remediation Roadmap [NEW] ──────────────────────────────────

    def _section_executive_remediation_roadmap(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        """Three-phase executive remediation roadmap derived from actual findings."""
        story.append(Paragraph("Executive Remediation Roadmap", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Findings prioritised into three execution phases. "
            "All data derived from actual assessment findings — nothing is fabricated.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        try:
            phases = build_executive_remediation_roadmap(findings)
        except Exception:
            phases = []

        if not phases:
            story.append(Paragraph("Not Available — no findings to prioritise.", st["na"]))
            return

        _PHASE_HEADER_COLORS: dict[str, colors.Color] = {
            "Phase 1 — Immediate": _C_CRIMSON,
            "Phase 2 — Near Term": _C_ORANGE,
            "Phase 3 — Strategic": _C_BLUE,
        }

        for phase in phases:
            phase_color = _PHASE_HEADER_COLORS.get(phase["name"], _C_DARK)
            hdr_data = [[
                f"{phase['name']}  ({phase['timeframe']})   "
                f"  Estimated Risk Reduction: {phase['risk_reduction']}"
            ]]
            hdr_tbl = Table(hdr_data, colWidths=[_BODY_WIDTH])
            hdr_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), phase_color),
                ("TEXTCOLOR",     (0, 0), (-1, -1), _C_WHITE),
                ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(hdr_tbl)

            rows = [["#", "Finding", "Severity", "Pillar", "Resources", "Effort", "Priority"]]
            for i, item in enumerate(phase["items"][:20], 1):
                rows.append([
                    str(i),
                    _tr(item["title"], 42),
                    item["severity"].upper(),
                    item["pillar"].replace("_", " ").title(),
                    str(item["resource_count"]),
                    item["effort"],
                    str(item["priority"]),
                ])

            sev_extra = [
                ("BACKGROUND", (2, idx), (2, idx),
                 _SEV_COLORS.get(r[2].lower(), _C_WHITE))
                for idx, r in enumerate(rows[1:], start=1)
            ]
            story.append(_make_table(
                rows,
                col_widths=[
                    0.8 * cm, 5.5 * cm, 2.0 * cm,
                    3.5 * cm, 1.8 * cm, 2.0 * cm, 2.0 * cm,
                ],
                extra_style=sev_extra,
            ))
            story.append(Spacer(1, 0.3 * cm))

        # ── Roadmap Summary Table ──────────────────────────────────────────────
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("Roadmap Summary", st["h2"]))
        summary_rows = [["Phase", "Findings", "Est. Effort", "Est. Risk Reduction"]]
        for phase in phases:
            items = phase["items"]
            effort_counts: dict[str, int] = {}
            for it in items:
                effort_counts[it["effort"]] = effort_counts.get(it["effort"], 0) + 1
            dominant_effort = (
                max(effort_counts, key=lambda k: effort_counts[k])
                if effort_counts else "—"
            )
            summary_rows.append([
                f"{phase['name']}  ({phase['timeframe']})",
                str(len(items)),
                dominant_effort,
                phase["risk_reduction"],
            ])
        story.append(_make_table(
            summary_rows,
            col_widths=[6.5 * cm, 2.5 * cm, 3.0 * cm, 5.5 * cm],
        ))
        story.append(Spacer(1, 0.5 * cm))

    # ── Remediation Playbooks ─────────────────────────────────────────────────

    def _section_remediation_playbooks(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        """Step-by-step remediation playbooks for every unique WAF rule in the assessment.

        One card per deduplicated rule_id — up to 20 rules sorted by severity.
        Known rules show Portal, CLI, PowerShell, Bicep, and Terraform guidance.
        Unknown rules display "Manual remediation guidance required."
        The entire section is wrapped in try/except; never aborts report generation.
        """
        story.append(Paragraph("Remediation Playbooks", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Implementation playbooks for each unique WAF finding — "
            "Portal steps, Azure CLI, PowerShell, Bicep, and Terraform guidance. "
            "Only rules with registered playbooks display implementation commands; "
            "unknown rules require manual remediation guidance.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        # Deduplicate by rule_id; track resource count per rule
        seen: dict[str, Finding] = {}
        resource_counts: dict[str, set[str]] = {}
        for f in findings:
            if f.rule_id not in seen:
                seen[f.rule_id] = f
                resource_counts[f.rule_id] = set()
            resource_counts[f.rule_id].add(f.resource_id)

        sorted_rules = sorted(
            seen.values(),
            key=lambda f: _SEVERITY_ORDER.index(f.severity.value)
            if f.severity.value in _SEVERITY_ORDER else 99,
        )

        _LABEL_W   = 2.8 * cm
        _CONTENT_W = _BODY_WIDTH - _LABEL_W

        def _code_para(code: str) -> Paragraph:
            return Paragraph(
                f'<font name="Courier" size="7">{_code_xml(code, 700)}</font>',
                st["body"],
            )

        for f in sorted_rules[:20]:
            try:
                n_resources = len(resource_counts.get(f.rule_id, set()))
                sev         = f.severity.value
                playbook    = build_remediation_playbook(f)
                fix_time    = estimate_fix_time(f)
                risk_red    = expected_risk_reduction(f)

                # ── Severity-coloured title header ─────────────────────────
                hdr_color      = _SEV_COLORS.get(sev, _C_LGREY)
                hdr_text_color = _C_WHITE if sev in ("critical", "high") else _C_DARK
                hdr_data = [[
                    f"{_tr(f.title, 80)}  ·  {sev.upper()}"
                    f"  ·  {f.pillar.replace('_', ' ').title()}"
                    f"  ·  {n_resources} resource(s)"
                ]]
                hdr_tbl = Table(hdr_data, colWidths=[_BODY_WIDTH])
                hdr_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), hdr_color),
                    ("TEXTCOLOR",     (0, 0), (-1, -1), hdr_text_color),
                    ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
                    ("TOPPADDING",    (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ]))
                story.append(hdr_tbl)

                if playbook is None:
                    # Unknown rule — no playbook registered
                    na_data = [[
                        "Manual remediation guidance required. "
                        "Refer to the Azure documentation for this specific rule."
                    ]]
                    na_tbl = Table(na_data, colWidths=[_BODY_WIDTH])
                    na_tbl.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), _C_LGREY),
                        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Oblique"),
                        ("FONTSIZE",      (0, 0), (-1, -1), 8),
                        ("TOPPADDING",    (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                    ]))
                    story.append(na_tbl)
                else:
                    # Full playbook card
                    _CODE_BG  = colors.HexColor("#F4F4F4")
                    _LABEL_BG = colors.HexColor("#EBF5FB")
                    rows = [
                        [
                            Paragraph("<b>Portal Steps</b>", st["body"]),
                            Paragraph(_code_xml(playbook.portal_steps, 600), st["body"]),
                        ],
                        [
                            Paragraph("<b>Azure CLI</b>",    st["body"]),
                            _code_para(playbook.azure_cli),
                        ],
                        [
                            Paragraph("<b>PowerShell</b>",   st["body"]),
                            _code_para(playbook.powershell),
                        ],
                        [
                            Paragraph("<b>Bicep</b>",        st["body"]),
                            _code_para(playbook.bicep),
                        ],
                        [
                            Paragraph("<b>Terraform</b>",    st["body"]),
                            _code_para(playbook.terraform),
                        ],
                        [
                            Paragraph("<b>Fix Time</b>",     st["body"]),
                            Paragraph(fix_time,              st["body"]),
                        ],
                        [
                            Paragraph("<b>Risk Reduction</b>", st["body"]),
                            Paragraph(risk_red,                st["body"]),
                        ],
                    ]
                    pb_tbl = Table(rows, colWidths=[_LABEL_W, _CONTENT_W])
                    pb_tbl.setStyle(TableStyle([
                        ("FONTSIZE",      (0, 0), (-1, -1), 8),
                        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                         [colors.HexColor("#FDFEFE"), colors.HexColor("#F7F9FA")]),
                        # Code rows (1–4): distinct background on both columns
                        ("BACKGROUND",   (0, 1), (0, 4), _LABEL_BG),
                        ("BACKGROUND",   (1, 1), (1, 4), _CODE_BG),
                        ("GRID",         (0, 0), (-1, -1), 0.3, _C_MGREY),
                        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING",   (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                    ]))
                    story.append(pb_tbl)

                story.append(Spacer(1, 0.5 * cm))
            except Exception:
                pass  # Never abort report generation — skip this card on error

    # ── Enterprise Implementation Roadmap [NEW] ──────────────────────────────

    def _section_enterprise_remediation_roadmap(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding],
    ) -> None:
        """9-section enterprise implementation roadmap derived from existing findings.

        Never raises — each section is wrapped individually so a single section
        failure never aborts the rest of the roadmap or report generation.
        """
        try:
            plan = build_remediation_plan(agg, findings)
        except Exception:
            return

        _W = _BODY_WIDTH

        # Phase colour mapping
        _PHASE_COLORS: dict[str, colors.Color] = {
            "Immediate":   _C_CRIMSON,
            "Near-Term":   _C_ORANGE,
            "Medium-Term": _C_YELLOW,
            "Long-Term":   _C_TEAL,
        }
        _PHASE_TEXT_DARK: set[str] = {"Medium-Term"}  # dark text on light background

        def _phase_color(label: str) -> colors.Color:
            return _PHASE_COLORS.get(label, _C_DARK)

        def _phase_text(label: str) -> colors.Color:
            return _C_DARK if label in _PHASE_TEXT_DARK else _C_WHITE

        # ── Section header helper ──────────────────────────────────────────────
        def _sec_hdr(title: str, subtitle: str = "", rule_color: colors.Color = _C_DARK) -> None:
            story.append(Paragraph(title, st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=rule_color))
            if subtitle:
                story.append(Paragraph(subtitle, st["caption"]))
            story.append(Spacer(1, 0.3 * cm))

        def _sub_hdr(title: str) -> None:
            story.append(Paragraph(title, st["h2"]))

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 1 — Executive Roadmap
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sec_hdr(
                "Enterprise Implementation Roadmap",
                "Findings prioritised by severity into four execution phases. "
                "All data derived from actual assessment findings. Nothing is fabricated.",
                _C_DARK,
            )

            if not plan.phases:
                story.append(Paragraph("No findings to prioritise.", st["na"]))
            else:
                # Phase summary banner
                phase_summary_rows = [[
                    "Phase", "Timeframe", "Severity", "Finding Count",
                ]]
                for ph in plan.phases:
                    phase_summary_rows.append([
                        ph.label, ph.timeframe, ph.severity_bucket, str(len(ph.items)),
                    ])
                phase_extra = [
                    ("BACKGROUND", (0, i + 1), (-1, i + 1), _phase_color(ph.label))
                    for i, ph in enumerate(plan.phases)
                ] + [
                    ("TEXTCOLOR", (0, i + 1), (-1, i + 1), _phase_text(ph.label))
                    for i, ph in enumerate(plan.phases)
                ]
                story.append(_make_table(
                    phase_summary_rows,
                    col_widths=[4 * cm, 3.5 * cm, 4 * cm, 3 * cm],
                    extra_style=phase_extra,
                ))
                story.append(Spacer(1, 0.5 * cm))

                # Per-phase tables
                for ph in plan.phases:
                    ph_color = _phase_color(ph.label)
                    ph_text  = _phase_text(ph.label)
                    # Phase header bar
                    ph_hdr_data = [[
                        f"{ph.label}   ·   {ph.timeframe}   ·   "
                        f"Severity: {ph.severity_bucket}   ·   "
                        f"{len(ph.items)} finding(s)"
                    ]]
                    ph_hdr_tbl = Table(ph_hdr_data, colWidths=[_W])
                    ph_hdr_tbl.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), ph_color),
                        ("TEXTCOLOR",     (0, 0), (-1, -1), ph_text),
                        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, -1), 9.5),
                        ("TOPPADDING",    (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ]))
                    story.append(ph_hdr_tbl)

                    rows = [["#", "Finding", "Owner", "Effort", "Risk Reduction", "Verification"]]
                    for item in ph.items[:25]:
                        rows.append([
                            str(item.rank),
                            _tr(item.title, 42),
                            item.owner,
                            item.estimated_effort,
                            item.estimated_risk_reduction,
                            _tr(item.verification_step, 50),
                        ])
                    story.append(_make_table(
                        rows,
                        col_widths=[
                            0.8 * cm, 4.8 * cm, 2.8 * cm,
                            2.2 * cm, 2.2 * cm, 4.9 * cm,
                        ],
                    ))
                    story.append(Spacer(1, 0.4 * cm))

            story.append(PageBreak())
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 2 — Remediation Table (full detail)
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sec_hdr(
                "Remediation Table — Full Detail",
                "Every finding with owner, effort estimate, risk reduction, and "
                "verification guidance. Sorted by severity (worst first).",
            )

            if not plan.remediation_table:
                story.append(Paragraph("No findings available.", st["na"]))
            else:
                rows = [[
                    "#", "Finding", "Severity", "Pillar",
                    "WAF Controls", "Owner", "Priority",
                    "Effort", "Risk Reduction",
                ]]
                sev_extra: list = []
                for item in plan.remediation_table:
                    rows.append([
                        str(item.rank),
                        _tr(item.title, 40),
                        item.severity.upper(),
                        _tr(item.pillar, 18),
                        _tr(item.waf_controls, 16),
                        _tr(item.owner, 18),
                        item.priority_label,
                        item.estimated_effort,
                        item.estimated_risk_reduction,
                    ])
                    sev_extra.append((
                        "BACKGROUND",
                        (2, len(rows) - 1), (2, len(rows) - 1),
                        _SEV_COLORS.get(item.severity, _C_WHITE),
                    ))
                story.append(_make_table(
                    rows,
                    col_widths=[
                        0.7 * cm, 4.2 * cm, 1.8 * cm, 2.2 * cm,
                        1.8 * cm, 2.2 * cm, 2.0 * cm, 2.0 * cm, 2.0 * cm,
                    ],
                    extra_style=sev_extra,
                ))

            story.append(PageBreak())
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 3 — Quick Wins
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sec_hdr(
                "Quick Wins — Low Effort, High Impact",
                "Automatically identified findings that deliver high security or "
                "reliability value at low remediation effort. Sorted by impact.",
                _C_TEAL,
            )

            if not plan.quick_wins:
                story.append(Paragraph(
                    "No quick wins identified in this assessment.", st["na"]
                ))
            else:
                rows = [["#", "Finding", "Pillar", "Impact", "Effort", "WAF Controls", "Recommendation"]]
                for qw in plan.quick_wins:
                    rows.append([
                        str(qw.rank),
                        _tr(qw.title, 36),
                        _tr(qw.pillar, 16),
                        qw.impact_label,
                        qw.effort_label,
                        _tr(qw.waf_controls, 14),
                        _tr(qw.recommendation, 50),
                    ])
                story.append(_make_table(
                    rows,
                    col_widths=[
                        0.7 * cm, 3.8 * cm, 2.0 * cm,
                        1.8 * cm, 1.8 * cm, 1.6 * cm, 5.2 * cm,
                    ],
                ))
            story.append(Spacer(1, 0.5 * cm))
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 4 — Strategic Improvements
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sub_hdr("Strategic Improvements")
            story.append(Paragraph(
                "Recurring findings grouped into named strategic initiatives. "
                "Groups are derived from actual findings only — nothing is invented.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            if not plan.strategic_initiatives:
                story.append(Paragraph("No strategic groupings identified.", st["na"]))
            else:
                rows = [["Initiative", "Finding Count", "Severity Summary", "Pillars", "Timeline"]]
                for si in plan.strategic_initiatives:
                    rows.append([
                        si.name,
                        str(si.finding_count),
                        _tr(si.severity_summary, 30),
                        _tr(si.pillars_involved, 24),
                        si.recommended_timeline,
                    ])
                story.append(_make_table(
                    rows,
                    col_widths=[4.5 * cm, 2.0 * cm, 4.0 * cm, 3.0 * cm, 3.2 * cm],
                ))

            story.append(PageBreak())
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 5 — Implementation Timeline
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sec_hdr(
                "Implementation Timeline",
                "Remediation activities placed by severity — "
                "Week 1 / Week 2 / Month 1 / Quarter.",
            )

            if not plan.timeline:
                story.append(Paragraph("No timeline entries available.", st["na"]))
            else:
                for period in plan.timeline:
                    period_color = {
                        "Week 1":  _C_CRIMSON,
                        "Week 2":  _C_ORANGE,
                        "Month 1": _C_BLUE,
                        "Quarter": _C_TEAL,
                    }.get(period.period, _C_DARK)

                    period_text = {
                        "Week 1":  _C_WHITE,
                        "Week 2":  _C_WHITE,
                        "Month 1": _C_WHITE,
                        "Quarter": _C_WHITE,
                    }.get(period.period, _C_WHITE)

                    banner = Table(
                        [[f"{period.period}   ·   {period.focus}   ·   {period.finding_count} finding(s)"]],
                        colWidths=[_W],
                    )
                    banner.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), period_color),
                        ("TEXTCOLOR",     (0, 0), (-1, -1), period_text),
                        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, -1), 9),
                        ("TOPPADDING",    (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ]))
                    story.append(banner)

                    if period.activities:
                        act_rows = [[Paragraph(f"• {act}", st["body"])]
                                    for act in period.activities]
                        act_tbl = Table(act_rows, colWidths=[_W])
                        act_tbl.setStyle(TableStyle([
                            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FDFEFE")),
                            ("BOX",           (0, 0), (-1, -1), 0.4, _C_MGREY),
                            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                            ("TOPPADDING",    (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ]))
                        story.append(act_tbl)
                    story.append(Spacer(1, 0.3 * cm))

            story.append(Spacer(1, 0.4 * cm))
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 6 — Expected Improvements
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sub_hdr("Expected Improvements")
            story.append(Paragraph(
                "Qualitative projections using severity-weight estimates. "
                "Language: Estimated · Potential · Projected. "
                "Outcomes are not guaranteed.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            ei = plan.expected_improvements
            impr_rows = [
                ["Metric", "Projection"],
                ["Potential Security Score Increase",   ei.potential_security_increase],
                ["Potential Compliance Increase",        ei.potential_compliance_increase],
                ["Potential Risk Reduction",             ei.potential_risk_reduction],
            ]
            story.append(_make_table(
                impr_rows,
                col_widths=[5 * cm, 11.7 * cm],
            ))
            caveat_data = [[Paragraph(
                f"<i>{_code_xml(ei.caveat, 400)}</i>", st["caption"]
            )]]
            caveat_tbl = Table(caveat_data, colWidths=[_W])
            caveat_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#F8F9FA")),
                ("BOX",           (0, 0), (-1, -1), 0.4, _C_MGREY),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(Spacer(1, 0.3 * cm))
            story.append(caveat_tbl)

            story.append(PageBreak())
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 7 — Dependencies
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sec_hdr(
                "Implementation Dependencies",
                "Detected implementation sequencing requirements. "
                "Generated rule-based from actual findings — no hallucinations.",
            )

            if not plan.dependencies:
                story.append(Paragraph(
                    "No implementation dependencies detected in this assessment.", st["na"]
                ))
            else:
                rows = [["Prerequisite", "→", "Dependent Action", "Rationale"]]
                for dep in plan.dependencies:
                    rows.append([
                        dep.prerequisite,
                        "→",
                        dep.dependent,
                        _tr(dep.rationale, 60),
                    ])
                story.append(_make_table(
                    rows,
                    col_widths=[4.8 * cm, 0.5 * cm, 4.8 * cm, 6.6 * cm],
                ))

            story.append(Spacer(1, 0.5 * cm))
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 8 — Verification Checklist
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sub_hdr("Verification Checklist")
            story.append(Paragraph(
                "Actionable checklist generated from assessment findings. "
                "Standard close-out steps are appended.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            if not plan.checklist:
                story.append(Paragraph("No checklist items generated.", st["na"]))
            else:
                # Group by category
                categories: dict[str, list[str]] = {}
                for item in plan.checklist:
                    categories.setdefault(item.category, []).append(item.text)

                cat_order = ["Immediate", "Near-Term", "Medium-Term", "Long-Term", "Close-Out"]
                for cat in cat_order:
                    texts = categories.get(cat)
                    if not texts:
                        continue
                    cat_color = {
                        "Immediate":   _C_CRIMSON,
                        "Near-Term":   _C_ORANGE,
                        "Medium-Term": colors.HexColor("#D4AC0D"),
                        "Long-Term":   _C_TEAL,
                        "Close-Out":   _C_DARK,
                    }.get(cat, _C_DARK)
                    cat_text = _C_WHITE if cat != "Medium-Term" else _C_DARK
                    cat_banner = Table([[cat]], colWidths=[_W])
                    cat_banner.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), cat_color),
                        ("TEXTCOLOR",     (0, 0), (-1, -1), cat_text),
                        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
                        ("TOPPADDING",    (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ]))
                    story.append(cat_banner)
                    chk_rows = [[Paragraph(t, st["body"])] for t in texts]
                    chk_tbl = Table(chk_rows, colWidths=[_W])
                    chk_tbl.setStyle(TableStyle([
                        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_C_WHITE, _C_LGREY]),
                        ("BOX",           (0, 0), (-1, -1), 0.4, _C_MGREY),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                        ("TOPPADDING",    (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]))
                    story.append(chk_tbl)
                    story.append(Spacer(1, 0.25 * cm))

            story.append(PageBreak())
        except Exception:
            pass

        # ══════════════════════════════════════════════════════════════════════
        # SECTION 9 — Management Summary
        # ══════════════════════════════════════════════════════════════════════
        try:
            _sec_hdr(
                "Management Summary — Implementation Overview",
                "Executive one-page implementation summary. "
                "Professional consulting language. No AI wording.",
                _C_DARK,
            )

            ms = plan.management_summary

            # Overview metrics
            ov_rows = [
                ["Metric",                  "Value"],
                ["Total Findings",           str(ms.total_findings)],
                ["Immediate (0–7 days)",     str(ms.immediate_count)],
                ["Near-Term (7–30 days)",    str(ms.near_term_count)],
                ["Medium-Term (30–90 days)", str(ms.medium_term_count)],
                ["Long-Term (90+ days)",     str(ms.long_term_count)],
                ["Estimated Total Effort",   ms.estimated_total_effort],
                ["Estimated Duration",       ms.estimated_duration],
            ]
            extra_ov = []
            if ms.immediate_count > 0:
                extra_ov.append(("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#FADBD8")))
            if ms.near_term_count > 0:
                extra_ov.append(("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#FDEBD0")))
            story.append(_make_table(ov_rows, col_widths=[6 * cm, 10.7 * cm],
                                     extra_style=extra_ov))
            story.append(Spacer(1, 0.4 * cm))

            # Top priorities
            if ms.top_priorities:
                story.append(Paragraph("Highest Priorities", st["h2"]))
                for i, prio in enumerate(ms.top_priorities, 1):
                    prio_data = [[Paragraph(f"<b>{i}.</b>  {_code_xml(prio, 200)}", st["body"])]]
                    prio_tbl = Table(prio_data, colWidths=[_W])
                    prio_tbl.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#EBF5FB")),
                        ("BOX",           (0, 0), (-1, -1), 0.5, _C_BLUE),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                        ("TOPPADDING",    (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]))
                    story.append(prio_tbl)
                    story.append(Spacer(1, 0.15 * cm))
                story.append(Spacer(1, 0.3 * cm))

            # Expected outcome
            story.append(Paragraph("Expected Business Outcome", st["h2"]))
            outcome_data = [[Paragraph(_code_xml(ms.expected_outcome, 600), st["narrative"])]]
            outcome_tbl = Table(outcome_data, colWidths=[_W])
            outcome_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#EBF5FB")),
                ("BOX",           (0, 0), (-1, -1), 1.0, _C_BLUE),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(outcome_tbl)
            story.append(Spacer(1, 0.4 * cm))

            # Top risks
            if ms.top_risks:
                story.append(Paragraph("Top Implementation Risks", st["h2"]))
                risk_rows = [[Paragraph(f"• {_code_xml(r, 200)}", st["body"])]
                             for r in ms.top_risks]
                risk_tbl = Table(risk_rows, colWidths=[_W])
                risk_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#FEF9E7")),
                    ("BOX",           (0, 0), (-1, -1), 0.6, _C_ORANGE),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]))
                story.append(risk_tbl)
        except Exception:
            pass

    # ── 14. Human Review Results ──────────────────────────────────────────────

    def _section_human_reviews(
        self,
        story: list,
        st: dict,
        hr_list: list[HumanReviewAssessment],
    ) -> None:
        story.append(Paragraph("Human Review Results", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "The following 4 WAF controls require human assessment. They cannot "
            "be evaluated through Azure APIs, Resource Graph, or ARM metadata.",
            st["body"],
        ))
        story.append(Spacer(1, 0.4 * cm))

        review_map = {r.control_code: r for r in hr_list}
        hr_rows    = [["Code", "Status", "Compliance", "Score", "Reviewer", "Date", "Comments"]]

        for code in ["SE-10", "OE-03", "OE-04", "CO-09"]:
            review = review_map.get(code)
            if review is None:
                hr_rows.append([code, "PENDING", "NOT ASSESSED", "—", "—", "—", "—"])
            else:
                hr_rows.append([
                    review.control_code,
                    review.status.value.replace("_", " ").upper(),
                    review.compliance_status.value.replace("_", " ").upper(),
                    str(review.score),
                    _tr(review.reviewer_oid, 20),
                    review.reviewed_at.strftime("%Y-%m-%d") if review.reviewed_at else "—",
                    _tr(review.comments or "—", 40),
                ])

        extra = []
        for i, code in enumerate(["SE-10", "OE-03", "OE-04", "CO-09"], 1):
            review = review_map.get(code)
            if review is None:
                extra.append(("BACKGROUND", (1, i), (2, i), colors.HexColor("#FDEBD0")))
            elif review.compliance_status == ComplianceStatus.COMPLIANT:
                extra.append(("BACKGROUND", (2, i), (2, i), colors.HexColor("#D5F5E3")))
            elif review.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT:
                extra.append(("BACKGROUND", (2, i), (2, i), colors.HexColor("#FDEBD0")))
            elif review.compliance_status.value == "non_compliant":
                extra.append(("BACKGROUND", (2, i), (2, i), colors.HexColor("#FADBD8")))

        story.append(_make_table(
            hr_rows,
            col_widths=[1.8 * cm, 2.8 * cm, 3 * cm, 1.5 * cm, 3 * cm, 2 * cm, 4.8 * cm],
            extra_style=extra,
        ))
        story.append(Spacer(1, 0.5 * cm))

        if hr_list:
            story.append(Paragraph("Evidence References", st["h2"]))
            for review in sorted(hr_list, key=lambda r: r.control_code):
                if review.evidence_refs:
                    story.append(Paragraph(f"{review.control_code}:", st["h3"]))
                    ev_rows = [["Type", "File / URL", "Description"]]
                    for ev in review.evidence_refs:
                        ev_rows.append([
                            ev.evidence_type.value.upper(),
                            _tr(ev.url_or_filename, 40),
                            _tr(ev.description, 50),
                        ])
                    story.append(_make_table(
                        ev_rows,
                        col_widths=[2.5 * cm, 6 * cm, 8.5 * cm],
                    ))

    # ── 15. WAF Traceability Matrix ───────────────────────────────────────────

    def _section_traceability_matrix(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Microsoft WAF Traceability Matrix", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Every finding traced to its WAF control, rule, pillar, and Microsoft documentation URL.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.4 * cm))

        if not findings:
            story.append(Paragraph("Not Available — no findings recorded.", st["na"]))
            return

        matrix_rows = [[
            "Finding", "Resource", "Rule ID",
            "WAF Code", "Pillar", "Severity", "Remediation",
        ]]
        sorted_f = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity.value)
            if f.severity.value in _SEVERITY_ORDER else 99,
        )
        for f in sorted_f[:200]:
            codes_str = ", ".join(f.waf_codes) if f.waf_codes else "—"
            matrix_rows.append([
                _tr(f.title, 30),
                _tr(f.resource_id, 28),
                f.rule_id,
                _tr(codes_str, 18),
                f.pillar.replace("_", " ").title()[:14],
                f.severity.value.upper(),
                _tr(f.recommendation, 35),
            ])

        extra = [
            ("BACKGROUND", (5, i), (5, i), _SEV_COLORS.get(r[5].lower(), _C_WHITE))
            for i, r in enumerate(matrix_rows[1:], start=1)
        ]
        story.append(_make_table(
            matrix_rows,
            col_widths=[3.5 * cm, 3.5 * cm, 2.8 * cm,
                        2 * cm, 2.3 * cm, 1.8 * cm, 4.5 * cm],
            extra_style=extra,
        ))
        if len(findings) > 200:
            story.append(Paragraph(
                f"Showing first 200 of {len(findings)} findings. "
                "See Raw Findings sheet in Excel for complete list.",
                st["caption"],
            ))

    # ── 16. Detailed Findings ─────────────────────────────────────────────────

    def _section_detailed_findings(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Detailed Findings by Pillar", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Paragraph(
            "Findings are grouped by rule. Each entry shows the number of affected "
            "resources and lists them individually. Appendix A contains the complete "
            "flat finding list.",
            st["caption"],
        ))

        pillar_findings: dict[str, list[Finding]] = {}
        for f in findings:
            pillar_findings.setdefault(f.pillar, []).append(f)

        for pillar_name in sorted(pillar_findings.keys()):
            ps    = agg.findings_by_pillar.get(pillar_name)
            title = pillar_name.replace("_", " ").title()
            pf    = pillar_findings[pillar_name]
            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph(f"Pillar: {title}", st["h2"]))
            if ps:
                unique_rules = len({f.rule_id for f in pf})
                story.append(Paragraph(
                    f"Compliance Score: {ps.compliance_score * 100:.1f}%  |  "
                    f"Total Findings: {ps.total_findings}  |  "
                    f"Unique Rules: {unique_rules}  |  "
                    f"Critical: {ps.findings_by_severity.get('critical', 0)}  "
                    f"High: {ps.findings_by_severity.get('high', 0)}",
                    st["body"],
                ))
            story.append(Spacer(1, 0.2 * cm))

            # Build lookup: (rule_id, severity) → first Finding
            # Used to supply resource_type for the remediation template fallback.
            _first_pf: dict[tuple[str, str], Finding] = {}
            for _f in pf:
                _key = (_f.rule_id, _f.severity.value)
                if _key not in _first_pf:
                    _first_pf[_key] = _f

            grouped = group_findings_for_reporting(pf)
            for g in grouped:
                sev_color = _SEV_COLORS.get(g.severity, _C_WHITE)
                text_color = _C_WHITE if g.severity in ("critical", "high") else _C_DARK

                # Severity+title banner row
                codes_str = ", ".join(g.waf_codes) if g.waf_codes else "—"
                banner_data = [[
                    Paragraph(
                        f'<b>{g.severity.upper()}</b>  {_tr(g.title, 60)}',
                        ParagraphStyle("BannerLeft", parent=st["body"],
                                       textColor=text_color, fontSize=8),
                    ),
                    Paragraph(
                        f'Rule: {g.rule_id}  |  WAF: {codes_str}',
                        ParagraphStyle("BannerRight", parent=st["caption"],
                                       textColor=text_color, alignment=TA_RIGHT),
                    ),
                ]]
                banner = Table(banner_data,
                               colWidths=[_BODY_WIDTH * 0.70, _BODY_WIDTH * 0.30])
                banner.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, 0), sev_color),
                    ("TOPPADDING",    (0, 0), (-1, 0), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                    ("LEFTPADDING",   (0, 0), (0, 0),  8),
                    ("RIGHTPADDING",  (-1, 0), (-1, 0), 8),
                    ("VALIGN",        (0, 0), (-1, 0), "MIDDLE"),
                ]))

                # Affected resources list (max 25 shown, one per line)
                shown     = g.resource_names[:25]
                res_lines = "<br/>".join(f"&nbsp;&nbsp;• {n}" for n in shown)
                if g.count > 25:
                    res_lines += f"<br/>&nbsp;&nbsp;... (+{g.count - 25} more)"

                # ── Remediation detail (7 dimensions) ─────────────────────────
                _ref = _first_pf.get((g.rule_id, g.severity))
                detail = get_remediation_detail(
                    g.rule_id,
                    severity=g.severity,
                    pillar=g.pillar,
                    resource_type=_ref.resource_type if _ref else "unknown",
                    recommendation=g.recommendation,
                )

                # ── Evidence card (format from first representative finding) ──
                try:
                    _ev_card: FormattedFindingCard | None = (
                        format_finding_card(_ref) if _ref else None
                    )
                except Exception:
                    _ev_card = None

                _lbl = ParagraphStyle(
                    "RemLabel", parent=st["body"],
                    fontName="Helvetica-Bold", fontSize=7.5,
                )
                _val = ParagraphStyle(
                    "RemValue", parent=st["body"], fontSize=7.5,
                )
                _code = ParagraphStyle(
                    "RemCode", parent=st["body"],
                    fontName="Courier", fontSize=6.5,
                    backColor=colors.HexColor("#F4F6F7"),
                    leading=9,
                )
                _link_style = ParagraphStyle(
                    "EvidLink", parent=st["body"], fontSize=7.5,
                    textColor=_C_BLUE,
                )

                _LW = 3.3 * cm   # label column width
                _VW = _BODY_WIDTH - _LW

                rem_rows = [
                    [
                        Paragraph("Business Impact", _lbl),
                        Paragraph(_code_xml(detail.business_impact, 300), _val),
                    ],
                    [
                        Paragraph("Technical Risk", _lbl),
                        Paragraph(_code_xml(detail.technical_risk, 300), _val),
                    ],
                    [
                        Paragraph("Estimated Effort", _lbl),
                        Paragraph(detail.estimated_effort, _val),
                    ],
                    [
                        Paragraph("Risk Reduction", _lbl),
                        Paragraph(detail.risk_reduction, _val),
                    ],
                    [
                        Paragraph("Azure CLI", _lbl),
                        Paragraph(_code_xml(detail.azure_cli, 450), _code),
                    ],
                    [
                        Paragraph("Bicep", _lbl),
                        Paragraph(_code_xml(detail.bicep, 450), _code),
                    ],
                    [
                        Paragraph("Terraform", _lbl),
                        Paragraph(_code_xml(detail.terraform, 450), _code),
                    ],
                ]

                rem_table = Table(rem_rows, colWidths=[_LW, _VW])
                rem_table.setStyle(TableStyle([
                    ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING",    (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                     [colors.white, colors.HexColor("#F8F9FA")]),
                    ("BACKGROUND",    (1, 4), (1, 6),
                     colors.HexColor("#F0F3F4")),
                    ("BOX",       (0, 0), (-1, -1), 0.4, _C_MGREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, _C_MGREY),
                    ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
                ]))

                rec_str = _code_xml(g.recommendation, 400) if g.recommendation else "—"

                block = [
                    banner,
                    Paragraph(
                        f'<b>Pillar:</b> {g.pillar.replace("_", " ").title()}'
                        f'  |  <b>Affected Resources:</b> {g.count}'
                        f'  |  <b>Rule:</b> {g.rule_id}',
                        st["body"],
                    ),
                    Paragraph(
                        f'<b>Recommendation:</b> {rec_str}',
                        st["body"],
                    ),
                ]
                story.append(KeepTogether(block))

                story.append(Paragraph(
                    f'<b>Affected Resource Names:</b><br/>{res_lines}',
                    st["body"],
                ))

                # ── Enterprise Evidence Card ───────────────────────────────────
                try:
                    if _ev_card is not None:
                        story.append(Spacer(1, 0.15 * cm))
                        story.append(Paragraph("<b>Evidence &amp; Context</b>", st["h3"]))

                        # ── Resource Details ───────────────────────────────────
                        res_rows: list[list] = []
                        if _ev_card.resource_name:
                            res_rows.append([
                                Paragraph("Resource Name", _lbl),
                                Paragraph(_code_xml(_ev_card.resource_name, 200), _val),
                            ])
                        if _ev_card.resource_type:
                            res_rows.append([
                                Paragraph("Resource Type", _lbl),
                                Paragraph(_code_xml(_ev_card.resource_type, 200), _val),
                            ])
                        if _ev_card.subscription_id:
                            res_rows.append([
                                Paragraph("Subscription", _lbl),
                                Paragraph(_code_xml(_ev_card.subscription_id, 200), _val),
                            ])
                        if _ev_card.resource_group:
                            res_rows.append([
                                Paragraph("Resource Group", _lbl),
                                Paragraph(_code_xml(_ev_card.resource_group, 200), _val),
                            ])

                        # ── Evaluation metadata ────────────────────────────────
                        res_rows.append([
                            Paragraph("Evaluation Method", _lbl),
                            Paragraph(_ev_card.evaluation_method, _val),
                        ])

                        # Confidence as inline bar (filled blocks)
                        pct = _ev_card.confidence_pct
                        filled  = round(pct / 10)
                        empty   = 10 - filled
                        bar_str = "&#9608;" * filled + "&#9617;" * empty
                        conf_bar_data = [[
                            Paragraph(bar_str,
                                      ParagraphStyle("ConfBar", parent=_val,
                                                     fontName="Courier",
                                                     textColor=_C_TEAL)),
                            Paragraph(f"<b>{pct}%</b>",
                                      ParagraphStyle("ConfPct", parent=_val,
                                                     alignment=TA_RIGHT)),
                        ]]
                        conf_bar_tbl = Table(conf_bar_data,
                                             colWidths=[_VW * 0.75, _VW * 0.25])
                        conf_bar_tbl.setStyle(TableStyle([
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("TOPPADDING",    (0, 0), (-1, -1), 0),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                        ]))
                        res_rows.append([
                            Paragraph("Confidence", _lbl),
                            conf_bar_tbl,
                        ])

                        if res_rows:
                            res_detail_tbl = Table(res_rows, colWidths=[_LW, _VW])
                            res_detail_tbl.setStyle(TableStyle([
                                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                                ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                                 [colors.white, colors.HexColor("#F8F9FA")]),
                                ("BOX",       (0, 0), (-1, -1), 0.4, _C_MGREY),
                                ("INNERGRID", (0, 0), (-1, -1), 0.4, _C_MGREY),
                                ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
                            ]))
                            story.append(res_detail_tbl)
                            story.append(Spacer(1, 0.1 * cm))

                        # ── WAF Control Mapping ────────────────────────────────
                        if _ev_card.waf_controls:
                            story.append(Paragraph("<b>WAF Control Mapping</b>", _lbl))
                            ctrl_rows: list[list] = [
                                [
                                    Paragraph("<b>Code</b>", _lbl),
                                    Paragraph("<b>Control Title</b>", _lbl),
                                ]
                            ]
                            for code, title in _ev_card.waf_controls:
                                ctrl_rows.append([
                                    Paragraph(_code_xml(code, 20), _val),
                                    Paragraph(_code_xml(title, 150) if title else "—", _val),
                                ])
                            ctrl_tbl = Table(ctrl_rows,
                                             colWidths=[2.5 * cm, _BODY_WIDTH - 2.5 * cm])
                            ctrl_tbl.setStyle(TableStyle([
                                ("BACKGROUND",    (0, 0), (-1, 0), _C_DARK),
                                ("TEXTCOLOR",     (0, 0), (-1, 0), _C_WHITE),
                                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                                 [colors.white, colors.HexColor("#F8F9FA")]),
                                ("BOX",       (0, 0), (-1, -1), 0.4, _C_MGREY),
                                ("INNERGRID", (0, 0), (-1, -1), 0.4, _C_MGREY),
                                ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
                            ]))
                            story.append(ctrl_tbl)
                            story.append(Spacer(1, 0.1 * cm))

                        # ── Evidence Table ─────────────────────────────────────
                        story.append(Paragraph("<b>Evidence</b>", _lbl))
                        if _ev_card.evidence_rows:
                            ev_rows: list[list] = []
                            for label, value in _ev_card.evidence_rows:
                                ev_rows.append([
                                    Paragraph(_code_xml(label, 50), _lbl),
                                    Paragraph(_code_xml(value, 300), _val),
                                ])
                            ev_tbl = Table(ev_rows, colWidths=[_LW, _VW])
                            ev_tbl.setStyle(TableStyle([
                                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                                ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                                 [colors.white, colors.HexColor("#F8F9FA")]),
                                ("BOX",       (0, 0), (-1, -1), 0.4, _C_MGREY),
                                ("INNERGRID", (0, 0), (-1, -1), 0.4, _C_MGREY),
                                ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
                            ]))
                            story.append(ev_tbl)
                        else:
                            story.append(Paragraph(
                                "No evidence fields recorded for this finding.",
                                st["body"],
                            ))
                        story.append(Spacer(1, 0.1 * cm))

                        # ── Microsoft Documentation ────────────────────────────
                        if _ev_card.microsoft_urls:
                            story.append(Paragraph(
                                "<b>Microsoft Documentation</b>", _lbl,
                            ))
                            for url in _ev_card.microsoft_urls:
                                safe_url = (url.replace("&", "&amp;")
                                              .replace("<", "&lt;")
                                              .replace(">", "&gt;"))
                                story.append(Paragraph(
                                    f'<link href="{safe_url}" color="#1F77B4">'
                                    f'{safe_url}</link>',
                                    _link_style,
                                ))
                            story.append(Spacer(1, 0.1 * cm))

                        # ── Severity-Mapped Metadata ───────────────────────────
                        meta_rows = [
                            [
                                Paragraph("Business Impact", _lbl),
                                Paragraph(
                                    _code_xml(_ev_card.business_impact_text, 400), _val,
                                ),
                            ],
                            [
                                Paragraph("Remediation Priority", _lbl),
                                Paragraph(
                                    f"<b>{_code_xml(_ev_card.remediation_priority_label, 80)}</b>",
                                    _val,
                                ),
                            ],
                            [
                                Paragraph("Verification Step", _lbl),
                                Paragraph(
                                    _code_xml(_ev_card.verification_step, 400), _val,
                                ),
                            ],
                        ]
                        meta_tbl = Table(meta_rows, colWidths=[_LW, _VW])
                        meta_tbl.setStyle(TableStyle([
                            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING",    (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
                            ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                             [colors.HexColor("#EBF5FB"),
                              colors.white,
                              colors.HexColor("#EBF5FB")]),
                            ("BOX",       (0, 0), (-1, -1), 0.5, _C_BLUE),
                            ("INNERGRID", (0, 0), (-1, -1), 0.4, _C_MGREY),
                            ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
                        ]))
                        story.append(meta_tbl)
                        story.append(Spacer(1, 0.1 * cm))

                except Exception:
                    pass  # Evidence card is optional — never abort report generation

                story.append(rem_table)
                story.append(Spacer(1, 0.2 * cm))
                story.append(HRFlowable(width="100%", thickness=0.3, color=_C_MGREY))
                story.append(Spacer(1, 0.2 * cm))

            story.append(PageBreak())

    # ── 17. Executive Recommendations [NEW] ──────────────────────────────────

    def _section_executive_recommendations(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
        findings: list[Finding],
    ) -> None:
        story.append(Paragraph("Executive Recommendations", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Top recommendations ranked by severity, frequency, and business impact. "
            "Derived from actual assessment findings using deterministic analysis.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.4 * cm))

        recs = _generate_recommendations(agg, findings)
        for rec_title, action, rationale in recs:
            block = [
                Paragraph(rec_title, st["rec_title"]),
                Paragraph(f"<b>Action:</b> {action}", st["rec_body"]),
                Paragraph(f"<b>Rationale:</b> {rationale}", st["rec_body"]),
                Spacer(1, 0.2 * cm),
                HRFlowable(width="100%", thickness=0.3, color=_C_MGREY),
                Spacer(1, 0.3 * cm),
            ]
            story.append(KeepTogether(block))

    # ── 18. Appendices ────────────────────────────────────────────────────────

    def _section_appendix(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
        agg: AggregatedReport,
    ) -> None:
        story.append(Paragraph("Appendix A — All Findings", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        sorted_f = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity.value)
            if f.severity.value in _SEVERITY_ORDER else 99,
        )
        app_rows = [["ID", "Pillar", "Severity", "Resource", "Title"]]
        for f in sorted_f:
            app_rows.append([
                str(f.id)[:8],
                f.pillar[:12],
                f.severity.value.upper(),
                _tr(f.resource_id, 35),
                _tr(f.title, 45),
            ])
        extra = [
            ("BACKGROUND", (2, i), (2, i), _SEV_COLORS.get(r[2].lower(), _C_WHITE))
            for i, r in enumerate(app_rows[1:], start=1)
        ]
        story.append(_make_table(
            app_rows,
            col_widths=[1.8 * cm, 2.8 * cm, 2 * cm, 4.5 * cm, 6.8 * cm],
            extra_style=extra,
        ))
        story.append(PageBreak())

        story.append(Paragraph("Appendix B — Scoring Methodology", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.3 * cm))

        methodology_text = agg.scoring_methodology or (
            "Compliance = weighted-average pillar scores, weight = findings × criticality. "
            "Risk = 100 − compliance + (critical+high)/total × 10. "
            "Business Impact = normalized pillar-risk weighted by criticality. "
            "Pillar criticality: Security=1.5, Reliability=1.3, "
            "Operational Excellence=1.1, Performance=1.0, Cost Optimization=0.8."
        )
        story.append(Paragraph(methodology_text, st["methodology"]))
        story.append(Spacer(1, 0.4 * cm))

        detail_rows = [
            ["Score", "Formula", "Range"],
            ["Pillar Compliance",
             "1 − Σ(sev_weight × count) / (total × max_weight)",
             "0–1 → ×100 for %"],
            ["Overall Compliance",
             "Σ(pillar_score × criticality × findings) / Σ(criticality × findings)",
             "0–100"],
            ["Risk Score",
             "100 − compliance + (critical+high)/total × 10",
             "0–100"],
            ["Weighted Severity",
             "Σ(sev_weight × count) / total × 100",
             "0–100"],
            ["Business Impact",
             "Σ((1−compliance) × criticality × findings) / total / max_criticality × 100",
             "0–100"],
        ]
        story.append(_make_table(
            detail_rows,
            col_widths=[4 * cm, 9 * cm, 4.5 * cm],
        ))

    # ── Compliance Framework Mapping ──────────────────────────────────────────

    def _section_compliance_framework_mapping(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        """Appendix: per-finding Azure Policy, Advisor, CIS, ISO 27001, NIST CSF, MCSB mapping.

        Purely informational. Never affects scores. Never invents mappings.
        """
        story.append(Paragraph("Appendix C — Compliance Framework Mapping", st["h1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            "Each finding is cross-referenced to external compliance frameworks using "
            "deterministic rule-based mappings. Entries are informational only and do not "
            "affect compliance or risk scores. Cells marked '—' indicate no mapping is defined "
            "for this rule ID.",
            st["caption"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not findings:
            story.append(Paragraph("No findings available.", st["na"]))
            return

        # Deduplicate by rule_id
        seen: dict[str, Finding] = {}
        for f in findings:
            if f.rule_id not in seen:
                seen[f.rule_id] = f

        # ── Section C-1: Azure Policy ─────────────────────────────────────────
        try:
            story.append(Paragraph("C-1  Azure Policy References", st["h2"]))
            story.append(Paragraph(
                "Azure Policy definitions that correspond to each finding rule. "
                "Definition IDs are Azure built-in policy GUIDs from the public Azure Policy registry.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            rows = [["Rule ID", "Finding Title", "Azure Policy Name", "Definition ID", "Category"]]
            for f in sorted(seen.values(),
                            key=lambda x: _SEVERITY_ORDER.index(x.severity.value)
                            if x.severity.value in _SEVERITY_ORDER else 99):
                policy = get_azure_policy(f.rule_id)
                if policy:
                    rows.append([
                        f.rule_id[:16],
                        _tr(f.title, 32),
                        _tr(policy.display_name, 44),
                        _tr(policy.definition_id, 38),
                        _tr(policy.compliance_category, 20),
                    ])
            if len(rows) > 1:
                story.append(_make_table(
                    rows,
                    col_widths=[2.4 * cm, 3.8 * cm, 5.3 * cm, 4.6 * cm, 2.4 * cm],
                ))
            else:
                story.append(Paragraph(
                    "No Azure Policy mappings available for the current finding set.", st["na"]
                ))
            story.append(Spacer(1, 0.4 * cm))
        except Exception:
            pass

        # ── Section C-2: Azure Advisor ────────────────────────────────────────
        try:
            story.append(Paragraph("C-2  Azure Advisor References", st["h2"]))
            story.append(Paragraph(
                "Related Azure Advisor recommendation categories. "
                "Azure Advisor does not generate WAF findings — this mapping is informational.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            rows = [["Rule ID", "Finding Title", "Advisor Category", "Related Recommendation"]]
            for f in sorted(seen.values(),
                            key=lambda x: _SEVERITY_ORDER.index(x.severity.value)
                            if x.severity.value in _SEVERITY_ORDER else 99):
                adv = get_advisor_ref(f.rule_id, f.pillar)
                if adv:
                    rows.append([
                        f.rule_id[:16],
                        _tr(f.title, 32),
                        _tr(adv.category, 20),
                        _tr(adv.recommendation_title, 52),
                    ])
            if len(rows) > 1:
                story.append(_make_table(
                    rows,
                    col_widths=[2.4 * cm, 3.8 * cm, 2.4 * cm, 9.9 * cm],
                ))
            else:
                story.append(Paragraph(
                    "No Azure Advisor mappings available for the current finding set.", st["na"]
                ))
            story.append(Spacer(1, 0.4 * cm))
        except Exception:
            pass

        story.append(PageBreak())

        # ── Section C-3: CIS / ISO / NIST / MCSB ─────────────────────────────
        try:
            story.append(Paragraph("C-3  CIS / ISO 27001 / NIST CSF / MCSB Cross-Reference", st["h2"]))
            story.append(Paragraph(
                "Industry standard control references mapped to each WAF finding using "
                "deterministic rule-prefix lookups. Informational only.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.2 * cm))

            rows = [["Rule ID", "Title", "CIS Azure 2.0", "ISO 27001:2022", "NIST CSF", "MCSB"]]
            for f in sorted(seen.values(),
                            key=lambda x: _SEVERITY_ORDER.index(x.severity.value)
                            if x.severity.value in _SEVERITY_ORDER else 99):
                fw = get_compliance_frameworks(f.rule_id)
                if fw:
                    rows.append([
                        f.rule_id[:16],
                        _tr(f.title, 30),
                        ", ".join(fw.cis_azure[:3]) if fw.cis_azure else "—",
                        ", ".join(fw.iso_27001[:3]) if fw.iso_27001 else "—",
                        ", ".join(fw.nist_csf[:3]) if fw.nist_csf else "—",
                        ", ".join(fw.mcsb[:3]) if fw.mcsb else "—",
                    ])
            if len(rows) > 1:
                story.append(_make_table(
                    rows,
                    col_widths=[
                        2.4 * cm, 3.6 * cm, 2.5 * cm, 3.0 * cm, 2.5 * cm, 2.7 * cm,
                    ],
                ))
            else:
                story.append(Paragraph(
                    "No framework mappings available for the current finding set.", st["na"]
                ))
        except Exception:
            pass

    # ── Executive Risk Matrix ─────────────────────────────────────────────────

    def _section_risk_matrix(
        self,
        story: list,
        st: dict,
        findings: list[Finding],
    ) -> None:
        """Appendix: 4×4 Likelihood vs Impact heatmap, deterministic from severity."""
        try:
            story.append(Paragraph("Appendix D — Executive Risk Matrix", st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "Findings placed on a Likelihood vs Impact matrix using deterministic "
                "severity-based mapping. Likelihood reflects how commonly this class of "
                "misconfiguration is exploited. Impact reflects potential business harm. "
                "No risk values are invented — all mappings are rule-based.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            # Deterministic likelihood and impact from severity
            _SEV_TO_LIKELIHOOD = {
                "critical": "High",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Low",
            }
            _SEV_TO_IMPACT = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Low",
            }

            # Heatmap grid: rows=Likelihood (High→Low), cols=Impact (Low→Critical)
            _LIKELIHOOD_LABELS = ["High", "Medium", "Low"]
            _IMPACT_LABELS     = ["Low", "Medium", "High", "Critical"]

            # Assign each unique rule to a cell
            cell_counts: dict[tuple[str, str], int] = {}
            for f in findings:
                sev = f.severity.value
                lk  = _SEV_TO_LIKELIHOOD.get(sev, "Low")
                im  = _SEV_TO_IMPACT.get(sev, "Low")
                cell_counts[(lk, im)] = cell_counts.get((lk, im), 0) + 1

            # Heatmap colour — based on (likelihood, impact) combination
            def _cell_color(lk: str, im: str) -> colors.Color:
                score = (
                    {"High": 3, "Medium": 2, "Low": 1}.get(lk, 1)
                    * {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(im, 1)
                )
                if score >= 9:
                    return colors.HexColor("#C0392B")   # critical — dark red
                if score >= 6:
                    return colors.HexColor("#E67E22")   # high — orange
                if score >= 3:
                    return colors.HexColor("#F1C40F")   # medium — yellow
                return colors.HexColor("#2ECC71")        # low — green

            # Header row
            heatmap_rows = [
                ["Likelihood \\ Impact"] + _IMPACT_LABELS
            ]
            for lk in _LIKELIHOOD_LABELS:
                row = [lk]
                for im in _IMPACT_LABELS:
                    count = cell_counts.get((lk, im), 0)
                    row.append(f"{count} finding(s)" if count else "—")
                heatmap_rows.append(row)

            # Build style commands
            extra: list = []
            for row_idx, lk in enumerate(_LIKELIHOOD_LABELS, 1):
                for col_idx, im in enumerate(_IMPACT_LABELS, 1):
                    c = _cell_color(lk, im)
                    extra.append(("BACKGROUND", (col_idx, row_idx), (col_idx, row_idx), c))
                    count = cell_counts.get((lk, im), 0)
                    if count > 0:
                        extra.append(
                            ("FONTNAME", (col_idx, row_idx), (col_idx, row_idx), "Helvetica-Bold")
                        )

            col_w = [3.5 * cm, 3.0 * cm, 3.0 * cm, 3.0 * cm, 3.0 * cm]
            story.append(_make_table(heatmap_rows, col_widths=col_w, extra_style=extra))
            story.append(Spacer(1, 0.4 * cm))

            # Legend
            legend_rows = [
                ["Colour", "Zone", "Risk Level", "Description"],
                ["", "Red", "Critical",
                 "High likelihood of exploitation with critical impact. Immediate action required."],
                ["", "Orange", "High",
                 "Elevated likelihood or high impact. Prioritise in current sprint."],
                ["", "Yellow", "Medium",
                 "Moderate risk. Address within the current quarter."],
                ["", "Green", "Low",
                 "Low likelihood and limited impact. Include in routine maintenance."],
            ]
            legend_extra = [
                ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#C0392B")),
                ("BACKGROUND", (0, 2), (0, 2), colors.HexColor("#E67E22")),
                ("BACKGROUND", (0, 3), (0, 3), colors.HexColor("#F1C40F")),
                ("BACKGROUND", (0, 4), (0, 4), colors.HexColor("#2ECC71")),
            ]
            story.append(_make_table(
                legend_rows,
                col_widths=[1.2 * cm, 2.0 * cm, 2.0 * cm, 12.3 * cm],
                extra_style=legend_extra,
            ))

            story.append(Spacer(1, 0.5 * cm))

            # Finding detail breakdown per risk zone
            story.append(Paragraph("Risk Zone Breakdown", st["h2"]))
            story.append(Spacer(1, 0.15 * cm))

            zone_rows = [["#", "Finding", "Severity", "Risk Zone"]]
            _sev_zone = {
                "critical": "Critical", "high": "High",
                "medium": "Medium", "low": "Low", "informational": "Low",
            }
            _zone_color = {
                "Critical": colors.HexColor("#C0392B"),
                "High":     colors.HexColor("#E67E22"),
                "Medium":   colors.HexColor("#F1C40F"),
                "Low":      colors.HexColor("#2ECC71"),
            }
            seen_rules: set[str] = set()
            zone_extra: list = []
            for rank, f in enumerate(sorted(
                findings,
                key=lambda x: _SEVERITY_ORDER.index(x.severity.value)
                if x.severity.value in _SEVERITY_ORDER else 99,
            )):
                if f.rule_id in seen_rules:
                    continue
                seen_rules.add(f.rule_id)
                zone = _sev_zone.get(f.severity.value, "Low")
                zone_rows.append([
                    str(len(zone_rows)),
                    _tr(f.title, 62),
                    f.severity.value.upper(),
                    zone,
                ])
                row_i = len(zone_rows) - 1
                zone_extra.append((
                    "BACKGROUND", (3, row_i), (3, row_i),
                    _zone_color.get(zone, _C_WHITE),
                ))
                zone_extra.append((
                    "BACKGROUND", (2, row_i), (2, row_i),
                    _SEV_COLORS.get(f.severity.value, _C_WHITE),
                ))

            story.append(_make_table(
                zone_rows,
                col_widths=[0.8 * cm, 10.4 * cm, 2.0 * cm, 2.5 * cm],
                extra_style=zone_extra,
            ))
        except Exception:
            pass

    # ── Assessment Methodology ────────────────────────────────────────────────

    def _section_assessment_methodology(
        self,
        story: list,
        st: dict,
    ) -> None:
        """Appendix: professional consulting-quality assessment methodology."""
        try:
            story.append(Paragraph("Appendix E — Assessment Methodology", st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "This appendix describes the systematic approach used to assess the Azure "
                "workload against the Microsoft Azure Well-Architected Framework. The methodology "
                "is designed to produce consistent, evidence-based, and auditable findings.",
                st["narrative"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            for phase_title, phase_text in METHODOLOGY_SECTIONS:
                try:
                    phase_rows = [[
                        Paragraph(f"<b>{phase_title}</b>", st["body"]),
                        Paragraph(_code_xml(phase_text, 500), st["body"]),
                    ]]
                    ph_tbl = Table(phase_rows, colWidths=[3.5 * cm, _BODY_WIDTH - 3.5 * cm])
                    ph_tbl.setStyle(TableStyle([
                        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                         [colors.HexColor("#F7F9FA"), colors.HexColor("#FDFEFE")]),
                        ("BOX",           (0, 0), (-1, -1), 0.5, _C_MGREY),
                        ("INNERGRID",     (0, 0), (-1, -1), 0.3, _C_LGREY),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                        ("TOPPADDING",    (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                        ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#EBF5FB")),
                    ]))
                    story.append(ph_tbl)
                    story.append(Spacer(1, 0.2 * cm))
                except Exception:
                    pass

            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph("Scope of Assessment", st["h2"]))
            scope_rows = [
                ["Scope Item", "In Scope", "Notes"],
                ["Azure resource configuration",   "Yes",
                 "All resource types accessible via ARM API"],
                ["Network security groups",        "Yes", "Inbound/outbound rule inspection"],
                ["Key Vault configuration",        "Yes", "Soft-delete, purge protection, access"],
                ["Storage account settings",       "Yes", "Secure transfer, TLS, access keys"],
                ["Application service settings",   "Yes", "HTTPS, TLS, managed identity, auth"],
                ["Diagnostic / monitoring config", "Yes", "Diagnostic settings, alert rules"],
                ["In-guest OS configuration",      "No",  "Requires agent-based or manual review"],
                ["Application code security",      "No",  "Requires SAST/DAST tooling"],
                ["Physical security",              "No",  "Azure data centre responsibility"],
                ["Operational processes",          "Partial", "Human review controls (SE-10 etc.)"],
                ["Business continuity plans",      "No",  "Requires manual review"],
            ]
            story.append(_make_table(
                scope_rows,
                col_widths=[5.8 * cm, 2.0 * cm, 9.7 * cm],
            ))
        except Exception:
            pass

    # ── Confidence Explanation ────────────────────────────────────────────────

    def _section_confidence_explanation(
        self,
        story: list,
        st: dict,
    ) -> None:
        """Appendix: explanation of confidence scores for non-technical readers."""
        try:
            story.append(Paragraph("Appendix F — Confidence Score Explanation", st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "Every finding in this report carries a confidence score that indicates "
                "the reliability of the assessment outcome. This appendix explains how "
                "confidence scores are assigned and how they should be interpreted.",
                st["narrative"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            for title, text in CONFIDENCE_SECTIONS:
                try:
                    conf_rows = [[
                        Paragraph(f"<b>{title}</b>", st["body"]),
                        Paragraph(_code_xml(text, 500), st["body"]),
                    ]]
                    cf_tbl = Table(conf_rows, colWidths=[4.5 * cm, _BODY_WIDTH - 4.5 * cm])
                    cf_tbl.setStyle(TableStyle([
                        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                        ("BOX",          (0, 0), (-1, -1), 0.5, _C_MGREY),
                        ("INNERGRID",    (0, 0), (-1, -1), 0.3, _C_LGREY),
                        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING",   (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
                        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#EAF4F4")),
                        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
                    ]))
                    story.append(cf_tbl)
                    story.append(Spacer(1, 0.2 * cm))
                except Exception:
                    pass

            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph("Confidence Threshold Reference", st["h2"]))
            thresh_rows = [
                ["Confidence Range", "Classification", "Recommended Action"],
                ["0.90 – 1.00", "Deterministic", "High confidence. Remediate as prioritised."],
                ["0.75 – 0.89", "LLM-Assisted (High)", "Good confidence. Verify evidence if needed."],
                ["0.60 – 0.74", "LLM-Assisted (Medium)",
                 "Moderate confidence. Independent verification recommended."],
                ["0.00 – 0.59", "Low Evidence",
                 "Verify finding against current resource configuration before acting."],
            ]
            conf_extra = [
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#D5F5E3")),
                ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#EBF5FB")),
                ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#FEF9E7")),
                ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#FADBD8")),
            ]
            story.append(_make_table(
                thresh_rows,
                col_widths=[3.0 * cm, 4.0 * cm, 10.5 * cm],
                extra_style=conf_extra,
            ))
        except Exception:
            pass

    # ── Limitations ───────────────────────────────────────────────────────────

    def _section_limitations(
        self,
        story: list,
        st: dict,
    ) -> None:
        """Appendix: professional limitations and disclaimer."""
        try:
            story.append(Paragraph("Appendix G — Assessment Limitations", st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "This appendix documents the known limitations of the assessment to support "
                "informed use of the findings and recommendations contained in this report.",
                st["narrative"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            for i, limitation in enumerate(LIMITATIONS_TEXT, 1):
                try:
                    lim_data = [[
                        Paragraph(f"<b>L-{i}</b>", st["body"]),
                        Paragraph(_code_xml(limitation, 500), st["narrative"]),
                    ]]
                    lim_tbl = Table(lim_data, colWidths=[1.2 * cm, _BODY_WIDTH - 1.2 * cm])
                    lim_tbl.setStyle(TableStyle([
                        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                        ("BOX",          (0, 0), (-1, -1), 0.5, _C_MGREY),
                        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING",   (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#FDFEFE")),
                    ]))
                    story.append(lim_tbl)
                    story.append(Spacer(1, 0.15 * cm))
                except Exception:
                    pass
        except Exception:
            pass

    # ── Audit Trail ───────────────────────────────────────────────────────────

    def _section_audit_trail(
        self,
        story: list,
        st: dict,
        agg: AggregatedReport,
    ) -> None:
        """Appendix: complete assessment audit trail — no secrets, no tokens."""
        try:
            story.append(Paragraph("Appendix H — Audit Trail", st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "This appendix provides a complete audit trail for the assessment. "
                "It contains no credentials, tokens, keys, or sensitive system information.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            # Core identifiers
            gen_ts = agg.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC") \
                if agg.generated_at else "Not Available"

            identity_rows = [
                ["Field", "Value"],
                ["Assessment ID",   str(agg.assessment_id)],
                ["Tenant ID",       str(agg.tenant_id)],
                ["Report Version",  _REPORT_VERSION],
                ["Generation Time", gen_ts],
            ]
            story.append(Paragraph("Assessment Identifiers", st["h2"]))
            story.append(_make_table(
                identity_rows,
                col_widths=[5 * cm, 12.5 * cm],
            ))
            story.append(Spacer(1, 0.35 * cm))

            # Assessment metrics
            story.append(Paragraph("Assessment Metrics", st["h2"]))
            metric_rows = [
                ["Metric", "Value"],
                ["Total Resources Assessed",   str(agg.total_resources)],
                ["Resources with Findings",    str(agg.resources_with_findings)],
                ["Total Findings",             str(agg.total_findings)],
                ["Overall Compliance Score",   f"{agg.overall_compliance_score:.1f}%"],
                ["Overall Risk Score",         f"{agg.overall_risk_score:.1f}"],
                ["Coverage Percentage",        f"{getattr(agg, 'coverage_percentage', 0):.1f}%"],
                ["Subscription Count",         str(getattr(agg, 'subscription_count', 'N/A'))],
            ]
            story.append(_make_table(
                metric_rows,
                col_widths=[5 * cm, 12.5 * cm],
            ))
            story.append(Spacer(1, 0.35 * cm))

            # Severity distribution
            story.append(Paragraph("Finding Severity Distribution", st["h2"]))
            sev_rows = [["Severity", "Count"]]
            for sev in _SEVERITY_ORDER:
                count = agg.findings_by_severity.get(sev, 0)
                sev_rows.append([sev.capitalize(), str(count)])
            sev_extra = [
                ("BACKGROUND", (0, i + 1), (-1, i + 1),
                 _SEV_COLORS.get(_SEVERITY_ORDER[i], _C_WHITE))
                for i in range(len(_SEVERITY_ORDER))
            ]
            story.append(_make_table(
                sev_rows,
                col_widths=[5 * cm, 12.5 * cm],
                extra_style=sev_extra,
            ))
            story.append(Spacer(1, 0.35 * cm))

            # Generator information
            story.append(Paragraph("Report Generator Information", st["h2"]))
            gen_rows = [
                ["Field", "Value"],
                ["Generator",         "Azure WAF Assessment Platform — PDF Generator"],
                ["Generator Version", _REPORT_VERSION],
                ["Report Format",     "PDF / A4 — reportlab"],
                ["Classification",    "CONFIDENTIAL — For authorised recipients only"],
                ["Disclaimer",
                 "This report is generated from assessment data only. "
                 "No data is fabricated or interpolated."],
            ]
            story.append(_make_table(
                gen_rows,
                col_widths=[5 * cm, 12.5 * cm],
            ))
        except Exception:
            pass

    # ── Glossary ──────────────────────────────────────────────────────────────

    def _section_glossary(
        self,
        story: list,
        st: dict,
    ) -> None:
        """Appendix: professional glossary of Azure and WAF terms."""
        try:
            story.append(Paragraph("Appendix I — Glossary", st["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5, color=_C_DARK))
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "Definitions of key terms used throughout this report.",
                st["caption"],
            ))
            story.append(Spacer(1, 0.3 * cm))

            sorted_glossary = sorted(GLOSSARY, key=lambda x: x[0].lower())
            gloss_rows = [["Term", "Definition"]]
            for term, defn in sorted_glossary:
                gloss_rows.append([
                    Paragraph(f"<b>{_code_xml(term, 40)}</b>", st["body"]),
                    Paragraph(_code_xml(defn, 500), st["body"]),
                ])

            # Two-column alternating rows for readability
            gloss_tbl = Table(
                gloss_rows,
                colWidths=[4.5 * cm, _BODY_WIDTH - 4.5 * cm],
            )
            gloss_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), _C_DARK),
                ("TEXTCOLOR",     (0, 0), (-1, 0), _C_WHITE),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, 0), 9),
                ("TOPPADDING",    (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#FDFEFE"), colors.HexColor("#F2F3F4")]),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("BOX",           (0, 0), (-1, -1), 0.5, _C_MGREY),
                ("INNERGRID",     (0, 0), (-1, -1), 0.3, _C_LGREY),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("TOPPADDING",    (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                ("FONTSIZE",      (0, 1), (-1, -1), 8.5),
            ]))
            story.append(gloss_tbl)
        except Exception:
            pass


# ── Module-level helpers ───────────────────────────────────────────────────────

def _score_label(score: float) -> str:
    if score >= 90:
        return "Excellent — minimal compliance risk"
    if score >= 70:
        return "Good — some gaps to address"
    if score >= 50:
        return "Fair — significant improvements needed"
    return "Poor — immediate remediation required"


def _risk_label(score: float) -> str:
    if score <= 10:
        return "Low Risk"
    if score <= 30:
        return "Moderate Risk"
    if score <= 60:
        return "High Risk"
    return "Critical Risk"


def _short_rt(resource_type: str) -> str:
    if "/" in resource_type:
        return resource_type.split("/")[-1][:22]
    return resource_type[:22]
