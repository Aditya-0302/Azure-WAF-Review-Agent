"""Executive dashboard builder — enterprise-grade visual dashboards for PDF & Excel.

Consumes ONLY existing AggregatedReport and Finding objects.
Never calls Azure, never performs new assessments, never modifies data.

Ten dashboards:
  D1.  Executive KPI Grid         — 9 large KPI tiles
  D2.  Pillar Performance Bars    — horizontal progress bars, Red/Amber/Green
  D3.  Severity Donut             — donut chart with percentage labels
  D4.  Compliance Radar           — pentagon radar over 5 pillars
  D5.  Top Resource Types         — horizontal bar by finding count, descending
  D6.  Risk Heatmap Grid          — severity × pillar cell grid, color-scaled
  D7.  Finding Trend Summary      — line chart or "unavailable" message
  D8.  Business Impact Breakdown  — stacked bar by impact category × severity
  D9.  Assessment Coverage        — 4 large metric tiles
  D10. Legend                     — colors, icons, scale explanation

Public API
----------
build_dashboard_data(agg, findings) -> DashboardData      # extract from existing objects
build_kpi_grid(data, w, h)          -> Drawing
build_pillar_bars(data, w, h)       -> Drawing
build_severity_donut(data, w, h)    -> Drawing
build_radar_chart(data, w, h)       -> Drawing
build_resource_type_bars(data, w, h) -> Drawing
build_risk_heatmap_grid(data, w, h) -> Drawing
build_trend_chart(data, w, h)       -> Drawing
build_business_impact_bars(data, w, h) -> Drawing
build_coverage_visual(data, w, h)   -> Drawing
build_legend_drawing(data, w, h)    -> Drawing

Every function is fully defensive — never raises, returns a "No data" placeholder
on any error so that report generation is never interrupted.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Sequence

from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import (
    Circle, Drawing, Line, Polygon, Rect, String,
)
from reportlab.lib import colors
from reportlab.lib.units import cm

from waf_reporting.aggregator import AggregatedReport
from waf_shared.domain.models.finding import Finding


# ---------------------------------------------------------------------------
# Colour constants
# ---------------------------------------------------------------------------

_C_DARK    = colors.HexColor("#2C3E50")
_C_BLUE    = colors.HexColor("#1F77B4")
_C_TEAL    = colors.HexColor("#16A085")
_C_GREEN   = colors.HexColor("#27AE60")
_C_AMBER   = colors.HexColor("#F1C40F")
_C_ORANGE  = colors.HexColor("#E67E22")
_C_RED     = colors.HexColor("#E74C3C")
_C_CRIMSON = colors.HexColor("#C0392B")
_C_LGREY   = colors.HexColor("#ECF0F1")
_C_MGREY   = colors.HexColor("#BDC3C7")
_C_WHITE   = colors.white

_SEV_COLORS: dict[str, colors.Color] = {
    "critical":      colors.HexColor("#C0392B"),
    "high":          colors.HexColor("#E67E22"),
    "medium":        colors.HexColor("#D4AC0D"),
    "low":           colors.HexColor("#1E8449"),
    "informational": colors.HexColor("#7F8C8D"),
}

_PILLAR_COLORS: list[colors.Color] = [
    colors.HexColor("#1F77B4"),
    colors.HexColor("#FF7F0E"),
    colors.HexColor("#2CA02C"),
    colors.HexColor("#D62728"),
    colors.HexColor("#9467BD"),
]

_IMPACT_COLORS: dict[str, colors.Color] = {
    "Security":             colors.HexColor("#C0392B"),
    "Business Continuity":  colors.HexColor("#1F77B4"),
    "Operational":          colors.HexColor("#E67E22"),
    "Cost":                 colors.HexColor("#27AE60"),
    "Performance":          colors.HexColor("#9467BD"),
}

_SEVERITY_ORDER  = ["critical", "high", "medium", "low", "informational"]
_PILLAR_ORDER    = [
    "security", "reliability", "operational_excellence",
    "performance_efficiency", "cost_optimization",
]
_PILLAR_DISPLAY  = {
    "security":               "Security",
    "reliability":            "Reliability",
    "operational_excellence": "Ops Excellence",
    "performance_efficiency": "Perf Efficiency",
    "cost_optimization":      "Cost Optim.",
}
_PILLAR_TO_IMPACT = {
    "security":               "Security",
    "reliability":            "Business Continuity",
    "operational_excellence": "Operational",
    "cost_optimization":      "Cost",
    "performance_efficiency": "Performance",
}
_HUMAN_REVIEW_CODES = frozenset({"SE-10", "OE-03", "OE-04", "CO-09"})


# ---------------------------------------------------------------------------
# Shared drawing helpers
# ---------------------------------------------------------------------------

def _no_data(width: float, height: float, msg: str = "No data available") -> Drawing:
    d = Drawing(width, height)
    d.add(Rect(2, 2, width - 4, height - 4,
               fillColor=_C_LGREY, strokeColor=_C_MGREY, strokeWidth=0.5))
    d.add(String(width / 2, height / 2 - 4, msg,
                 fontSize=8, textAnchor="middle",
                 fillColor=colors.HexColor("#7F8C8D")))
    return d


def _score_color(score: float) -> colors.Color:
    if score >= 90:
        return _C_GREEN
    if score >= 70:
        return _C_AMBER
    if score >= 50:
        return _C_ORANGE
    return _C_RED


def _short_type(full: str) -> str:
    """Shorten Azure resource type to readable label."""
    seg = full.rsplit("/", 1)[-1]
    RENAMES = {
        "storageaccounts":      "Storage Accounts",
        "virtualmachines":      "Virtual Machines",
        "sites":                "App Services",
        "servers":              "SQL Servers",
        "vaults":               "Key Vaults",
        "applicationgateways":  "App Gateways",
        "namespaces":           "Service Bus",
        "workspaces":           "Log Analytics",
        "registries":           "Container Registries",
        "managedclusters":      "AKS Clusters",
        "disks":                "Managed Disks",
        "networkinterfaces":    "Network Interfaces",
        "publicipaddresses":    "Public IPs",
        "networkSecurityGroups":"NSGs",
        "networksecuritygroups":"NSGs",
        "loadbalancers":        "Load Balancers",
        "virtualnetworks":      "VNets",
    }
    key = seg.lower()
    return RENAMES.get(key, seg.replace("_", " ").title()[:22])


# ---------------------------------------------------------------------------
# DashboardData dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DashboardData:
    """Presentation-ready data extracted from AggregatedReport + findings."""

    # KPI values
    overall_score: float
    compliance_pct: float
    risk_score: float
    total_resources: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    human_reviews_required: int

    # Pillar data: {pillar_key: score_0_to_100}
    pillar_scores: dict[str, float]

    # Severity counts per pillar: {pillar_key: {severity: count}}
    pillar_severity_counts: dict[str, dict[str, int]]

    # Severity distribution
    severity_counts: dict[str, int]

    # Resource types by finding count: [(short_label, count)], descending, max 10
    resource_type_counts: list[tuple[str, int]]

    # Heatmap: {severity: {pillar_key: count}}
    heatmap: dict[str, dict[str, int]]

    # Trend data (from historical assessments)
    trend_dates: list[str]
    trend_scores: list[float]

    # Business impact: {category_label: {severity: count}}
    impact_severity_counts: dict[str, dict[str, int]]

    # Coverage
    resources_assessed: int
    resources_with_findings: int
    human_review_findings: int
    distinct_rules_assessed: int


# ---------------------------------------------------------------------------
# Data extraction (no new calculations — reads existing objects only)
# ---------------------------------------------------------------------------

def build_dashboard_data(
    agg: AggregatedReport,
    findings: Sequence[Finding],
) -> DashboardData:
    """Extract and organise dashboard data from existing report objects.

    Never raises — returns empty/default DashboardData on any error.
    """
    try:
        sev = agg.findings_by_severity
        crit = sev.get("critical", 0)
        high = sev.get("high",     0)
        med  = sev.get("medium",   0)
        low  = sev.get("low",      0)
        info = sev.get("informational", 0)

        # Human reviews required: findings touching any human-review WAF code
        hr_count = sum(
            1 for f in findings
            if any(c in _HUMAN_REVIEW_CODES for c in (f.waf_codes or []))
        )

        # Pillar scores (0-100) — prefer weighted pass-rate scores when available
        pillar_scores: dict[str, float] = {}
        pillar_sev_counts: dict[str, dict[str, int]] = {}
        weighted_scores = getattr(agg, "pillar_scores", {})
        for pk, ps in agg.findings_by_pillar.items():
            pillar_scores[pk] = weighted_scores.get(pk, round(ps.compliance_score * 100, 1))
            pillar_sev_counts[pk] = dict(ps.findings_by_severity)

        # Resource type finding counts (top 10, descending)
        rt_raw: dict[str, int] = {}
        for f in findings:
            short = _short_type(f.resource_type)
            rt_raw[short] = rt_raw.get(short, 0) + 1
        rt_sorted = sorted(rt_raw.items(), key=lambda x: x[1], reverse=True)[:10]

        # Heatmap: {severity: {pillar: count}}
        heatmap: dict[str, dict[str, int]] = {
            s: {p: 0 for p in _PILLAR_ORDER} for s in _SEVERITY_ORDER
        }
        for f in findings:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            pillar_key = f.pillar
            if sev_key in heatmap and pillar_key in heatmap[sev_key]:
                heatmap[sev_key][pillar_key] += 1

        # Trend data from agg.trend_data
        trend_dates: list[str] = []
        trend_scores: list[float] = []
        for td in sorted(
            getattr(agg, "trend_data", []),
            key=lambda x: x.assessment_date,
        ):
            trend_dates.append(td.assessment_date.strftime("%b %Y"))
            trend_scores.append(round(td.compliance_score * 100, 1))
        # Append current assessment
        trend_dates.append("Current")
        trend_scores.append(round(agg.overall_compliance_score, 1))

        # Business impact breakdown: {category: {severity: count}}
        impact_counts: dict[str, dict[str, int]] = {
            cat: {s: 0 for s in _SEVERITY_ORDER}
            for cat in _IMPACT_COLORS
        }
        for f in findings:
            cat = _PILLAR_TO_IMPACT.get(f.pillar, "Operational")
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if cat in impact_counts and sev_key in impact_counts[cat]:
                impact_counts[cat][sev_key] += 1

        return DashboardData(
            overall_score         = round(agg.overall_compliance_score, 1),
            compliance_pct        = round(agg.overall_compliance_score, 1),
            risk_score            = round(agg.overall_risk_score, 1),
            total_resources       = agg.total_resources,
            total_findings        = agg.total_findings,
            critical_count        = crit,
            high_count            = high,
            medium_count          = med,
            low_count             = low,
            info_count            = info,
            human_reviews_required= hr_count,
            pillar_scores         = pillar_scores,
            pillar_severity_counts= pillar_sev_counts,
            severity_counts       = dict(sev),
            resource_type_counts  = rt_sorted,
            heatmap               = heatmap,
            trend_dates           = trend_dates,
            trend_scores          = trend_scores,
            impact_severity_counts= impact_counts,
            resources_assessed    = agg.total_resources,
            resources_with_findings = agg.resources_with_findings,
            human_review_findings = hr_count,
            distinct_rules_assessed = len({f.rule_id for f in findings}),
        )
    except Exception:
        return DashboardData(
            overall_score=0.0, compliance_pct=0.0, risk_score=0.0,
            total_resources=0, total_findings=0, critical_count=0,
            high_count=0, medium_count=0, low_count=0, info_count=0,
            human_reviews_required=0, pillar_scores={}, pillar_severity_counts={},
            severity_counts={}, resource_type_counts=[], heatmap={},
            trend_dates=[], trend_scores=[], impact_severity_counts={},
            resources_assessed=0, resources_with_findings=0,
            human_review_findings=0, distinct_rules_assessed=0,
        )


# ---------------------------------------------------------------------------
# D1: Executive KPI Grid
# ---------------------------------------------------------------------------

def build_kpi_grid(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 7.5 * cm,
) -> Drawing:
    """3×3 grid of coloured enterprise KPI tiles."""
    try:
        d = Drawing(width, height)

        kpis = [
            ("Overall Score",      f"{data.overall_score:.1f}",    "0–100 composite",  _score_color(data.overall_score)),
            ("Compliance",         f"{data.compliance_pct:.1f}%",  "WAF posture",      _score_color(data.compliance_pct)),
            ("Risk Score",         f"{data.risk_score:.1f}",       "Lower is better",  _C_CRIMSON if data.risk_score > 50 else _C_ORANGE if data.risk_score > 25 else _C_GREEN),
            ("Total Resources",    str(data.total_resources),       "Assessed",         _C_BLUE),
            ("Total Findings",     str(data.total_findings),        "Open issues",      _C_DARK),
            ("Critical / High",    f"{data.critical_count} / {data.high_count}", "Immediate action", _C_CRIMSON if data.critical_count > 0 else _C_ORANGE),
            ("Medium",             str(data.medium_count),          "Within 30 days",   _C_AMBER if data.medium_count > 0 else _C_GREEN),
            ("Low",                str(data.low_count),             "Next cycle",       _C_TEAL),
            ("Human Reviews",      str(data.human_reviews_required),"Require review",   _C_BLUE),
        ]

        cols = 3
        rows = 3
        gap  = 0.25 * cm
        card_w = (width - (cols + 1) * gap) / cols
        card_h = (height - (rows + 1) * gap) / rows

        for idx, (title, value, subtitle, fill) in enumerate(kpis):
            col_i = idx % cols
            row_i = idx // cols
            x = gap + col_i * (card_w + gap)
            y = height - gap - (row_i + 1) * card_h - row_i * gap

            # Shadow
            d.add(Rect(x + 1.5, y - 1.5, card_w, card_h,
                       fillColor=colors.HexColor("#A9A9A9"), strokeColor=None))
            # Card face
            d.add(Rect(x, y, card_w, card_h, fillColor=fill, strokeColor=None))

            # Value (large, bold)
            d.add(String(
                x + card_w / 2, y + card_h * 0.44,
                value, fontSize=13, fontName="Helvetica-Bold",
                textAnchor="middle", fillColor=_C_WHITE,
            ))
            # Title
            d.add(String(
                x + card_w / 2, y + card_h * 0.20,
                title, fontSize=6.5, fontName="Helvetica-Bold",
                textAnchor="middle", fillColor=_C_WHITE,
            ))
            # Subtitle
            d.add(String(
                x + card_w / 2, y + card_h * 0.05,
                subtitle, fontSize=5.5, fontName="Helvetica",
                textAnchor="middle",
                fillColor=colors.Color(1, 1, 1, alpha=0.75),
            ))

        return d
    except Exception:
        return _no_data(width, height, "KPI data unavailable")


# ---------------------------------------------------------------------------
# D2: Pillar Performance Bars
# ---------------------------------------------------------------------------

def build_pillar_bars(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 7 * cm,
) -> Drawing:
    """Horizontal progress bars per pillar, coloured Red/Amber/Green."""
    try:
        ps = data.pillar_scores
        if not ps:
            return _no_data(width, height, "No pillar data")

        pillars   = [p for p in _PILLAR_ORDER if p in ps] + [
            p for p in sorted(ps) if p not in _PILLAR_ORDER
        ]
        n         = len(pillars)
        label_w   = width * 0.26
        bar_area  = width * 0.58
        pct_x     = label_w + bar_area + 0.22 * cm
        row_h     = (height - 1.2 * cm) / n
        gap       = 0.09 * cm

        d = Drawing(width, height)
        d.add(String(
            width / 2, height - 0.32 * cm,
            "Pillar Compliance Performance",
            fontSize=9, fontName="Helvetica-Bold",
            textAnchor="middle", fillColor=_C_DARK,
        ))

        for i, pillar in enumerate(pillars):
            score = ps[pillar]
            y     = height - 1.1 * cm - (i + 1) * row_h + gap
            bar_h = row_h - 2 * gap
            fill  = _score_color(score)
            label = _PILLAR_DISPLAY.get(pillar, pillar.replace("_", " ").title())

            # Label
            d.add(String(
                label_w - 0.18 * cm, y + bar_h * 0.24,
                label, fontSize=7, fontName="Helvetica",
                textAnchor="end", fillColor=_C_DARK,
            ))
            # Background track
            d.add(Rect(label_w, y, bar_area, bar_h,
                       fillColor=_C_LGREY,
                       strokeColor=_C_MGREY, strokeWidth=0.3))
            # Filled bar
            fill_w = bar_area * min(score, 100.0) / 100
            if fill_w > 0:
                d.add(Rect(label_w, y, fill_w, bar_h,
                           fillColor=fill, strokeColor=None))
            # Score label
            d.add(String(
                pct_x, y + bar_h * 0.24,
                f"{score:.1f}%",
                fontSize=7, fontName="Helvetica-Bold",
                textAnchor="start", fillColor=_C_DARK,
            ))

        # Reference lines 70% / 90%
        bar_top = height - 1.1 * cm
        bar_bot = height - 1.1 * cm - n * row_h + gap
        for ref_pct, ref_col in [(70, _C_ORANGE), (90, _C_GREEN)]:
            rx = label_w + bar_area * ref_pct / 100
            d.add(Rect(rx, bar_bot, 0.6, bar_top - bar_bot,
                       fillColor=ref_col, strokeColor=None))
            d.add(String(rx, bar_top + 0.05 * cm, f"{ref_pct}%",
                         fontSize=5.5, textAnchor="middle", fillColor=ref_col))

        # Threshold legend
        for j, (lbl, col) in enumerate([
            ("≥90 Excellent", _C_GREEN),
            ("≥70 Good",      _C_AMBER),
            ("≥50 Fair",      _C_ORANGE),
            ("<50 Critical",  _C_RED),
        ]):
            lx = label_w + j * 2.8 * cm
            ly = height - 0.85 * cm
            d.add(Rect(lx, ly, 0.22 * cm, 0.16 * cm, fillColor=col, strokeColor=None))
            d.add(String(lx + 0.28 * cm, ly + 0.01 * cm, lbl,
                         fontSize=5.2, textAnchor="start",
                         fillColor=colors.HexColor("#555555")))

        return d
    except Exception:
        return _no_data(width, height, "Pillar performance data unavailable")


# ---------------------------------------------------------------------------
# D3: Severity Donut
# ---------------------------------------------------------------------------

def build_severity_donut(
    data: DashboardData,
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Donut chart with severity colours, percentage labels, and total in centre."""
    try:
        counts  = [data.severity_counts.get(s, 0) for s in _SEVERITY_ORDER]
        total   = sum(counts)
        if total == 0:
            return _no_data(width, height, "No findings")

        active_sevs   = [(s, c) for s, c in zip(_SEVERITY_ORDER, counts) if c > 0]
        active_data   = [c for _, c in active_sevs]
        active_colors = [_SEV_COLORS[s] for s, _ in active_sevs]
        active_labels = [s.capitalize() for s, _ in active_sevs]

        d  = Drawing(width, height)
        cx = width * 0.38
        r  = min(width * 0.28, height * 0.42)

        pie = Pie()
        pie.x              = int(cx - r)
        pie.y              = int(height / 2 - r)
        pie.width          = int(2 * r)
        pie.height         = int(2 * r)
        pie.data           = active_data
        pie.innerRadiusFraction = 0.48
        pie.slices.strokeWidth  = 1.0
        pie.slices.strokeColor  = _C_WHITE
        for i, col in enumerate(active_colors):
            pie.slices[i].fillColor = col
        d.add(pie)

        # Centre labels
        d.add(String(cx, height / 2 + 5, str(total),
                     fontSize=14, fontName="Helvetica-Bold",
                     textAnchor="middle", fillColor=_C_DARK))
        d.add(String(cx, height / 2 - 8, "total",
                     fontSize=7, fontName="Helvetica",
                     textAnchor="middle", fillColor=colors.HexColor("#7F8C8D")))

        # Legend (right side)
        legend_x = width * 0.72
        legend_y = height - 0.6 * cm
        for i, (sev, cnt) in enumerate(active_sevs):
            pct = cnt / total * 100
            ly  = legend_y - i * 1.05 * cm
            d.add(Rect(legend_x, ly - 0.05 * cm, 0.25 * cm, 0.22 * cm,
                       fillColor=_SEV_COLORS[sev], strokeColor=None))
            d.add(String(legend_x + 0.32 * cm, ly,
                         f"{sev.capitalize()}: {cnt} ({pct:.0f}%)",
                         fontSize=6.8, fontName="Helvetica",
                         textAnchor="start", fillColor=_C_DARK))

        return d
    except Exception:
        return _no_data(width, height, "Severity distribution unavailable")


# ---------------------------------------------------------------------------
# D4: Compliance Radar Chart (pentagon)
# ---------------------------------------------------------------------------

def build_radar_chart(
    data: DashboardData,
    width: float = 14 * cm,
    height: float = 10 * cm,
) -> Drawing:
    """Pentagon radar chart — one axis per WAF pillar, 0–100 scale."""
    try:
        ps = data.pillar_scores
        if not ps:
            return _no_data(width, height, "No pillar data for radar")

        pillars = [p for p in _PILLAR_ORDER if p in ps]
        if len(pillars) < 3:
            pillars = sorted(ps.keys())
        scores  = [ps[p] / 100.0 for p in pillars]
        n       = len(pillars)

        d  = Drawing(width, height)
        cx = width / 2
        cy = height / 2
        R  = min(width, height) * 0.36   # outer radius

        # Angles: start at top (π/2), go counter-clockwise
        angles = [math.pi / 2 + 2 * math.pi * i / n for i in range(n)]

        def vertex(r_frac: float, i: int) -> tuple[float, float]:
            a = angles[i]
            return cx + r_frac * R * math.cos(a), cy + r_frac * R * math.sin(a)

        # Background concentric polygons (25%, 50%, 75%, 100%)
        for frac, col in [
            (1.00, colors.HexColor("#ECF0F1")),
            (0.75, colors.HexColor("#D5D8DC")),
            (0.50, colors.HexColor("#BDC3C7")),
            (0.25, colors.HexColor("#ABB2B9")),
        ]:
            pts = []
            for i in range(n):
                vx, vy = vertex(frac, i)
                pts.extend([vx, vy])
            d.add(Polygon(pts, fillColor=col, strokeColor=_C_WHITE, strokeWidth=0.4))

        # Axis spokes
        for i in range(n):
            vx, vy = vertex(1.0, i)
            d.add(Line(cx, cy, vx, vy,
                       strokeColor=_C_MGREY, strokeWidth=0.5))

        # Score polygon (filled)
        score_pts = []
        for i, sc in enumerate(scores):
            vx, vy = vertex(sc, i)
            score_pts.extend([vx, vy])
        d.add(Polygon(
            score_pts,
            fillColor=colors.Color(0.121, 0.467, 0.706, alpha=0.45),
            strokeColor=_C_BLUE,
            strokeWidth=1.5,
        ))

        # Score vertex dots
        for i, sc in enumerate(scores):
            vx, vy = vertex(sc, i)
            d.add(Circle(vx, vy, 3.5, fillColor=_C_BLUE, strokeColor=_C_WHITE,
                         strokeWidth=0.8))

        # Pillar labels (outside the polygon)
        for i, pillar in enumerate(pillars):
            lx, ly = vertex(1.16, i)
            label  = _PILLAR_DISPLAY.get(pillar, pillar.replace("_", " ").title())
            score_val = f"{ps[pillar]:.0f}%"
            d.add(String(lx, ly + 4, label,
                         fontSize=6.5, fontName="Helvetica-Bold",
                         textAnchor="middle", fillColor=_C_DARK))
            d.add(String(lx, ly - 6, score_val,
                         fontSize=6, fontName="Helvetica",
                         textAnchor="middle", fillColor=_C_BLUE))

        # Scale labels at 25/50/75/100 along the first axis
        for frac, lbl in [(0.25, "25"), (0.50, "50"), (0.75, "75"), (1.00, "100")]:
            vx, vy = vertex(frac, 0)
            d.add(String(vx + 3, vy,
                         lbl, fontSize=5, textAnchor="start",
                         fillColor=colors.HexColor("#7F8C8D")))

        # Title
        d.add(String(cx, height - 0.2 * cm, "Pillar Compliance Radar",
                     fontSize=8, fontName="Helvetica-Bold",
                     textAnchor="middle", fillColor=_C_DARK))

        return d
    except Exception:
        return _no_data(width, height, "Radar chart unavailable")


# ---------------------------------------------------------------------------
# D5: Top Resource Types
# ---------------------------------------------------------------------------

def build_resource_type_bars(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Horizontal bars — finding count by resource type, descending."""
    try:
        items = data.resource_type_counts
        if not items:
            return _no_data(width, height, "No resource type data")

        n        = min(len(items), 10)
        items    = items[:n]
        max_cnt  = max(c for _, c in items) or 1

        label_w  = width * 0.34
        bar_area = width * 0.48
        count_x  = label_w + bar_area + 0.20 * cm
        row_h    = (height - 1.0 * cm) / n
        gap      = 0.08 * cm

        d = Drawing(width, height)
        d.add(String(
            width / 2, height - 0.32 * cm,
            "Top Resource Types by Finding Count",
            fontSize=9, fontName="Helvetica-Bold",
            textAnchor="middle", fillColor=_C_DARK,
        ))

        for i, (label, cnt) in enumerate(items):
            y     = height - 0.9 * cm - (i + 1) * row_h + gap
            bar_h = row_h - 2 * gap
            frac  = cnt / max_cnt
            # Color: more findings = worse
            fill  = (_C_RED if frac > 0.75 else
                     _C_ORANGE if frac > 0.40 else
                     _C_AMBER if frac > 0.15 else _C_TEAL)

            d.add(String(label_w - 0.15 * cm, y + bar_h * 0.24,
                         label[:26], fontSize=6.5, textAnchor="end",
                         fillColor=_C_DARK))
            d.add(Rect(label_w, y, bar_area, bar_h,
                       fillColor=_C_LGREY, strokeColor=_C_MGREY, strokeWidth=0.3))
            fill_w = bar_area * frac
            if fill_w > 0:
                d.add(Rect(label_w, y, fill_w, bar_h,
                           fillColor=fill, strokeColor=None))
            d.add(String(count_x, y + bar_h * 0.24, str(cnt),
                         fontSize=6.5, fontName="Helvetica-Bold",
                         textAnchor="start", fillColor=_C_DARK))

        return d
    except Exception:
        return _no_data(width, height, "Resource type data unavailable")


# ---------------------------------------------------------------------------
# D6: Risk Heatmap Grid
# ---------------------------------------------------------------------------

def build_risk_heatmap_grid(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 7 * cm,
) -> Drawing:
    """Severity × Pillar cell grid, colour-scaled by finding count."""
    try:
        heatmap = data.heatmap
        if not heatmap:
            return _no_data(width, height, "No heatmap data")

        def _cell_color(cnt: int) -> colors.Color:
            if cnt == 0:
                return colors.HexColor("#F2F3F4")
            if cnt <= 2:
                return colors.HexColor("#FCF3CF")
            if cnt <= 5:
                return colors.HexColor("#F9A825")
            return colors.HexColor("#E74C3C")

        def _text_color(cnt: int) -> colors.Color:
            return _C_WHITE if cnt > 5 else _C_DARK

        severities = [s for s in _SEVERITY_ORDER if s in heatmap]
        pillars    = [p for p in _PILLAR_ORDER
                      if any(p in heatmap.get(s, {}) for s in severities)]
        if not severities or not pillars:
            return _no_data(width, height, "Insufficient heatmap data")

        n_rows   = len(severities)
        n_cols   = len(pillars)
        margin_l = 2.4 * cm
        margin_b = 1.0 * cm
        margin_t = 0.5 * cm
        grid_w   = width - margin_l - 0.3 * cm
        grid_h   = height - margin_b - margin_t
        cell_w   = grid_w / n_cols
        cell_h   = grid_h / n_rows

        d = Drawing(width, height)

        # Title
        d.add(String(width / 2, height - 0.28 * cm, "Risk Heatmap — Severity × Pillar",
                     fontSize=9, fontName="Helvetica-Bold",
                     textAnchor="middle", fillColor=_C_DARK))

        # Column headers (pillar short names)
        for j, pillar in enumerate(pillars):
            cx = margin_l + (j + 0.5) * cell_w
            d.add(String(cx, margin_b + grid_h + 0.05 * cm,
                         _PILLAR_DISPLAY.get(pillar, pillar)[:12],
                         fontSize=5.5, fontName="Helvetica-Bold",
                         textAnchor="middle", fillColor=_C_DARK))

        # Row headers (severity)
        for i, sev in enumerate(severities):
            ry = margin_b + (n_rows - i - 1) * cell_h + cell_h * 0.3
            d.add(String(margin_l - 0.12 * cm, ry,
                         sev.capitalize(), fontSize=6.5,
                         textAnchor="end", fillColor=_SEV_COLORS.get(sev, _C_DARK)))

        # Grid cells
        for i, sev in enumerate(severities):
            for j, pillar in enumerate(pillars):
                cnt   = heatmap.get(sev, {}).get(pillar, 0)
                cx    = margin_l + j * cell_w
                cy    = margin_b + (n_rows - i - 1) * cell_h
                fill  = _cell_color(cnt)
                tcol  = _text_color(cnt)

                d.add(Rect(cx, cy, cell_w - 1, cell_h - 1,
                           fillColor=fill, strokeColor=_C_WHITE, strokeWidth=0.6))
                d.add(String(cx + cell_w / 2 - 0.5, cy + cell_h * 0.28,
                             str(cnt) if cnt > 0 else "—",
                             fontSize=7, fontName="Helvetica-Bold",
                             textAnchor="middle", fillColor=tcol))

        # Legend
        for k, (cnt_range, col, lbl) in enumerate([
            (0,  colors.HexColor("#F2F3F4"), "0"),
            (1,  colors.HexColor("#FCF3CF"), "1–2"),
            (3,  colors.HexColor("#F9A825"), "3–5"),
            (6,  colors.HexColor("#E74C3C"), "6+"),
        ]):
            lx = margin_l + k * 2.8 * cm
            ly = 0.10 * cm
            d.add(Rect(lx, ly, 0.22 * cm, 0.18 * cm, fillColor=col,
                       strokeColor=_C_MGREY, strokeWidth=0.3))
            d.add(String(lx + 0.28 * cm, ly + 0.01 * cm, lbl,
                         fontSize=5.5, textAnchor="start",
                         fillColor=colors.HexColor("#555555")))

        return d
    except Exception:
        return _no_data(width, height, "Heatmap unavailable")


# ---------------------------------------------------------------------------
# D7: Finding Trend Summary
# ---------------------------------------------------------------------------

def build_trend_chart(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 6.5 * cm,
) -> Drawing:
    """Line chart over historical assessments, or 'unavailable' if no history."""
    try:
        dates  = data.trend_dates
        scores = data.trend_scores

        if len(dates) < 2 or len(scores) < 2:
            d = Drawing(width, height)
            d.add(Rect(2, 2, width - 4, height - 4,
                       fillColor=colors.HexColor("#F8F9FA"),
                       strokeColor=_C_MGREY, strokeWidth=0.5))
            d.add(String(width / 2, height / 2 + 6,
                         "Historical Comparison Unavailable",
                         fontSize=9, fontName="Helvetica-Bold",
                         textAnchor="middle", fillColor=_C_DARK))
            d.add(String(width / 2, height / 2 - 8,
                         "This is the first assessed report — no prior data exists.",
                         fontSize=7, textAnchor="middle",
                         fillColor=colors.HexColor("#7F8C8D")))
            return d

        n       = len(dates)
        lm, rm  = 1.5 * cm, 2.0 * cm
        bm, tm  = 1.3 * cm, 0.5 * cm
        chart_w = width - lm - rm
        chart_h = height - bm - tm
        ox      = lm
        oy      = bm

        d = Drawing(width, height)
        d.add(String(width / 2, height - 0.28 * cm,
                     "Compliance Score Trend (%)",
                     fontSize=9, fontName="Helvetica-Bold",
                     textAnchor="middle", fillColor=_C_DARK))

        # Y-axis grid lines and labels
        for tick in [0, 20, 40, 60, 80, 100]:
            ty = oy + chart_h * tick / 100
            d.add(Rect(ox, ty, chart_w, 0.4,
                       fillColor=colors.HexColor("#ECF0F1"), strokeColor=None))
            d.add(String(ox - 0.1 * cm, ty - 3, f"{tick}",
                         fontSize=5.5, textAnchor="end",
                         fillColor=colors.HexColor("#7F8C8D")))

        # 90% target reference line
        ref_y = oy + chart_h * 0.90
        d.add(Rect(ox, ref_y, chart_w, 0.7,
                   fillColor=colors.HexColor("#27AE60"), strokeColor=None))
        d.add(String(ox + chart_w + 0.1 * cm, ref_y - 3, "90%",
                     fontSize=5.5, textAnchor="start",
                     fillColor=colors.HexColor("#27AE60")))

        # X-axis labels
        for i, label in enumerate(dates):
            px = ox + i * chart_w / max(n - 1, 1)
            d.add(String(px, oy - 0.9 * cm, label,
                         fontSize=5.5, textAnchor="middle",
                         fillColor=colors.HexColor("#7F8C8D")))

        # Line segments
        pts = [
            (ox + i * chart_w / max(n - 1, 1),
             oy + chart_h * min(scores[i], 100) / 100)
            for i in range(n)
        ]
        for i in range(len(pts) - 1):
            x1, y1 = pts[i]
            x2, y2 = pts[i + 1]
            d.add(Line(x1, y1, x2, y2,
                       strokeColor=_C_BLUE, strokeWidth=2.0))

        # Dots and score labels
        for i, (px, py) in enumerate(pts):
            fill = _C_WHITE if i < len(pts) - 1 else _C_TEAL
            d.add(Circle(px, py, 3.5, fillColor=fill,
                         strokeColor=_C_BLUE, strokeWidth=1.5))
            d.add(String(px, py + 5, f"{scores[i]:.0f}",
                         fontSize=5.5, textAnchor="middle",
                         fillColor=_C_DARK))

        return d
    except Exception:
        return _no_data(width, height, "Trend data unavailable")


# ---------------------------------------------------------------------------
# D8: Business Impact Breakdown
# ---------------------------------------------------------------------------

def build_business_impact_bars(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 7.5 * cm,
) -> Drawing:
    """Stacked horizontal bar — findings per impact category, coloured by severity."""
    try:
        imp = data.impact_severity_counts
        if not imp:
            return _no_data(width, height, "No business impact data")

        cats     = [c for c in _IMPACT_COLORS if c in imp]
        if not cats:
            return _no_data(width, height, "No business impact data")

        max_tot  = max((sum(imp[c].values()) for c in cats), default=1) or 1
        n        = len(cats)
        label_w  = width * 0.24
        bar_area = width * 0.55
        count_x  = label_w + bar_area + 0.20 * cm
        row_h    = (height - 1.2 * cm) / n
        gap      = 0.09 * cm

        d = Drawing(width, height)
        d.add(String(
            width / 2, height - 0.32 * cm,
            "Business Impact Breakdown by Category",
            fontSize=9, fontName="Helvetica-Bold",
            textAnchor="middle", fillColor=_C_DARK,
        ))

        for i, cat in enumerate(cats):
            sev_cts = imp[cat]
            total   = sum(sev_cts.values())
            y       = height - 1.1 * cm - (i + 1) * row_h + gap
            bar_h   = row_h - 2 * gap

            d.add(String(label_w - 0.15 * cm, y + bar_h * 0.24,
                         cat, fontSize=7, textAnchor="end", fillColor=_C_DARK))
            d.add(Rect(label_w, y, bar_area, bar_h,
                       fillColor=_C_LGREY, strokeColor=_C_MGREY, strokeWidth=0.3))

            x_off = 0.0
            for sev in _SEVERITY_ORDER:
                cnt = sev_cts.get(sev, 0)
                if cnt == 0:
                    continue
                seg_w = bar_area * cnt / max_tot
                d.add(Rect(label_w + x_off, y, seg_w, bar_h,
                           fillColor=_SEV_COLORS[sev], strokeColor=None))
                x_off += seg_w

            d.add(String(count_x, y + bar_h * 0.24, str(total) if total else "—",
                         fontSize=6.5, fontName="Helvetica-Bold",
                         textAnchor="start", fillColor=_C_DARK))

        # Severity legend
        for j, sev in enumerate(_SEVERITY_ORDER):
            lx = label_w + j * 2.2 * cm
            ly = height - 0.85 * cm
            d.add(Rect(lx, ly, 0.22 * cm, 0.16 * cm,
                       fillColor=_SEV_COLORS[sev], strokeColor=None))
            d.add(String(lx + 0.28 * cm, ly + 0.01 * cm, sev.capitalize(),
                         fontSize=5.2, textAnchor="start",
                         fillColor=colors.HexColor("#555555")))

        return d
    except Exception:
        return _no_data(width, height, "Business impact data unavailable")


# ---------------------------------------------------------------------------
# D9: Assessment Coverage
# ---------------------------------------------------------------------------

def build_coverage_visual(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 5.5 * cm,
) -> Drawing:
    """Four large metric tiles showing assessment scope and coverage."""
    try:
        no_findings = max(0, data.resources_assessed - data.resources_with_findings)
        rule_cov_pct = (
            round(data.distinct_rules_assessed / 57 * 100, 1)
            if data.distinct_rules_assessed > 0 else 0.0
        )
        tiles = [
            ("Resources Assessed",   str(data.resources_assessed),
             "Total in scope",        _C_BLUE),
            ("With Findings",         str(data.resources_with_findings),
             "Have open issues",      _C_RED if data.resources_with_findings > 0 else _C_GREEN),
            ("Clean Resources",       str(no_findings),
             "No findings",           _C_GREEN),
            ("Human Review Findings", str(data.human_review_findings),
             "Require expert review", _C_AMBER if data.human_review_findings > 0 else _C_TEAL),
        ]

        n      = len(tiles)
        gap    = 0.25 * cm
        card_w = (width - (n + 1) * gap) / n
        card_h = height - 2 * gap

        d = Drawing(width, height)
        for i, (title, value, subtitle, fill) in enumerate(tiles):
            x = gap + i * (card_w + gap)
            y = gap
            d.add(Rect(x + 1.5, y - 1.5, card_w, card_h,
                       fillColor=colors.HexColor("#A9A9A9"), strokeColor=None))
            d.add(Rect(x, y, card_w, card_h, fillColor=fill, strokeColor=None))
            d.add(String(x + card_w / 2, y + card_h * 0.50,
                         value, fontSize=16, fontName="Helvetica-Bold",
                         textAnchor="middle", fillColor=_C_WHITE))
            d.add(String(x + card_w / 2, y + card_h * 0.26,
                         title, fontSize=6.5, fontName="Helvetica-Bold",
                         textAnchor="middle", fillColor=_C_WHITE))
            d.add(String(x + card_w / 2, y + card_h * 0.09,
                         subtitle, fontSize=5.5,
                         textAnchor="middle",
                         fillColor=colors.Color(1, 1, 1, alpha=0.75)))
        return d
    except Exception:
        return _no_data(width, height, "Coverage data unavailable")


# ---------------------------------------------------------------------------
# D10: Legend
# ---------------------------------------------------------------------------

def build_legend_drawing(
    data: DashboardData,
    width: float = 17 * cm,
    height: float = 12 * cm,
) -> Drawing:
    """Static professional legend explaining all visual conventions."""
    try:
        d = Drawing(width, height)

        # Title
        d.add(String(width / 2, height - 0.32 * cm,
                     "Dashboard Legend & Visual Conventions",
                     fontSize=10, fontName="Helvetica-Bold",
                     textAnchor="middle", fillColor=_C_DARK))

        section_items: list[tuple[str, list[tuple[str, colors.Color, str]]]] = [
            ("Severity Colours", [
                ("Critical",      colors.HexColor("#C0392B"), "Immediate action required (0–24 h)"),
                ("High",          colors.HexColor("#E67E22"), "Action required within 7 days"),
                ("Medium",        colors.HexColor("#D4AC0D"), "Action required within 30 days"),
                ("Low",           colors.HexColor("#1E8449"), "Next maintenance cycle"),
                ("Informational", colors.HexColor("#7F8C8D"), "Monitor / review quarterly"),
            ]),
            ("Compliance Score Thresholds", [
                ("≥ 90% — Excellent",  colors.HexColor("#27AE60"), "Enterprise-grade posture"),
                ("≥ 70% — Good",       colors.HexColor("#F1C40F"), "Satisfactory; improvement advised"),
                ("≥ 50% — Fair",       colors.HexColor("#E67E22"), "Remediation required"),
                ("< 50% — Critical",   colors.HexColor("#E74C3C"), "Urgent remediation required"),
            ]),
            ("Business Impact Categories", [
                ("Security",            colors.HexColor("#C0392B"), "Security pillar findings"),
                ("Business Continuity", colors.HexColor("#1F77B4"), "Reliability pillar findings"),
                ("Operational",         colors.HexColor("#E67E22"), "Operational Excellence findings"),
                ("Cost",                colors.HexColor("#27AE60"), "Cost Optimization findings"),
                ("Performance",         colors.HexColor("#9467BD"), "Performance Efficiency findings"),
            ]),
            ("Risk Heatmap Scale", [
                ("0 findings",   colors.HexColor("#F2F3F4"), "Clean — no findings in this cell"),
                ("1–2 findings", colors.HexColor("#FCF3CF"), "Low concentration"),
                ("3–5 findings", colors.HexColor("#F9A825"), "Moderate concentration"),
                ("6+ findings",  colors.HexColor("#E74C3C"), "High concentration — prioritise"),
            ]),
        ]

        col_w  = width / 2
        x_pad  = 0.5 * cm
        y_cur  = height - 0.8 * cm
        row_h  = 0.38 * cm
        sec_h  = 0.48 * cm

        for col_i, (section_title, items) in enumerate(section_items):
            col_x = x_pad + col_i * col_w
            # Re-stack sections vertically in each column
            if col_i == 2:
                y_cur = height - 0.8 * cm
            if col_i == 3:
                y_cur -= 0.0  # same column as index 2, continued below

            # Actually lay out side-by-side in two columns
            # col 0,1 left; col 2,3 right — recompute
            col_side = col_i % 2  # 0=left, 1=right
            if col_i == 0:
                yl = height - 0.8 * cm
            if col_i == 1:
                yr = height - 0.8 * cm

            # Simpler: just lay all four sections top-to-bottom staggered
            break  # use simple approach below

        y_cur = height - 0.78 * cm
        left_x  = x_pad
        right_x = width / 2 + x_pad

        for sec_idx, (section_title, items) in enumerate(section_items):
            sx = left_x if sec_idx % 2 == 0 else right_x
            # If right section, reset y when we start the first right section
            if sec_idx == 1:
                y_cur_r = height - 0.78 * cm
            if sec_idx == 3:
                pass  # continues from sec_idx==1 position

            # Section header
            if sec_idx % 2 == 0:
                y_sec = y_cur
            else:
                if sec_idx == 1:
                    y_sec = height - 0.78 * cm
                    y_r = y_sec
                else:
                    y_sec = y_r

            d.add(Rect(sx, y_sec - 0.02 * cm, col_w - 2 * x_pad, sec_h - 0.04 * cm,
                       fillColor=_C_DARK, strokeColor=None))
            d.add(String(sx + 0.15 * cm, y_sec + 0.06 * cm, section_title,
                         fontSize=7, fontName="Helvetica-Bold",
                         textAnchor="start", fillColor=_C_WHITE))

            row_y = y_sec - sec_h
            for label, col, desc in items:
                d.add(Rect(sx + 0.1 * cm, row_y + 0.03 * cm, 0.25 * cm, 0.22 * cm,
                           fillColor=col, strokeColor=_C_MGREY, strokeWidth=0.3))
                d.add(String(sx + 0.42 * cm, row_y + 0.07 * cm,
                             f"{label}  —  {desc}",
                             fontSize=6, textAnchor="start", fillColor=_C_DARK))
                row_y -= row_h

            if sec_idx % 2 == 0:
                y_cur = row_y - 0.2 * cm
            else:
                y_r = row_y - 0.2 * cm

        # Confidence bar explanation
        note_y = min(y_cur, y_r) - 0.2 * cm if 'y_r' in dir() else y_cur - 0.2 * cm
        d.add(String(x_pad, note_y,
                     "Confidence Bar:  ████████░░  80%  "
                     "= 8 filled blocks out of 10.  Derived from assessment confidence_score.",
                     fontSize=6, textAnchor="start", fillColor=_C_DARK))
        d.add(String(x_pad, note_y - row_h,
                     "Evaluation Method:  'Deterministic Rule' = automated rule engine.  "
                     "'LLM Review' = AI-assisted evaluation.",
                     fontSize=6, textAnchor="start", fillColor=_C_DARK))

        return d
    except Exception:
        return _no_data(width, height, "Legend unavailable")
