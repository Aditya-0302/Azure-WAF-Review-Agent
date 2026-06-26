"""Reportlab-native chart helpers for enterprise PDF reports.

All charts are returned as reportlab Drawing objects, which are directly
flowable in a Platypus story.  No external chart libraries required.

Available charts:
  build_severity_pie          — donut-style pie for finding severity distribution
  build_pillar_bar            — horizontal bar chart for per-pillar compliance scores
  build_resource_bar          — horizontal bar chart for resource type compliance
  build_trend_line            — line chart for compliance trend over time
  build_kpi_cards             — KPI card row for cover page dashboard
  build_risk_heatmap          — heat-bar chart for security scorecard
  build_resource_group_bar    — horizontal bar chart for resource-group compliance
  build_findings_by_pillar_stacked — stacked bar by pillar/severity
  build_top_risk_contributors — weighted risk score bars by resource type
  build_compliance_breakdown  — progress bars with 70%/90% reference lines
  build_compliance_roadmap    — vertical milestone bar chart for remediation stages
  build_waf_benchmark_chart   — horizontal bullet chart: current vs WAF target per pillar
"""

from __future__ import annotations

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.units import cm

# ── Colour palette ─────────────────────────────────────────────────────────────

_SEV_COLORS = [
    colors.HexColor("#FF0000"),  # critical
    colors.HexColor("#FF6600"),  # high
    colors.HexColor("#FFCC00"),  # medium
    colors.HexColor("#CCE5FF"),  # low
    colors.HexColor("#DDDDDD"),  # informational
]

_PILLAR_COLORS = [
    colors.HexColor("#1F77B4"),
    colors.HexColor("#FF7F0E"),
    colors.HexColor("#2CA02C"),
    colors.HexColor("#D62728"),
    colors.HexColor("#9467BD"),
]

_PASS_COLOR = colors.HexColor("#2ECC71")
_FAIL_COLOR = colors.HexColor("#E74C3C")
_NA_COLOR = colors.HexColor("#BDC3C7")

_TREND_LINE_COLOR = colors.HexColor("#1F77B4")

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


# ── Public builders ────────────────────────────────────────────────────────────


def build_severity_pie(
    findings_by_severity: dict[str, int],
    width: float = 10 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Pie chart showing finding distribution by severity."""
    d = Drawing(width, height)

    counts = [findings_by_severity.get(s, 0) for s in _SEVERITY_ORDER]
    total = sum(counts)
    if total == 0:
        _no_data_label(d, width, height, "No findings")
        return d

    pie = Pie()
    pie.x = int(width * 0.15)
    pie.y = int(height * 0.15)
    pie.width = int(min(width, height) * 0.55)
    pie.height = pie.width
    pie.data = [c for c in counts if c > 0]
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white

    active_labels = [s for s, c in zip(_SEVERITY_ORDER, counts, strict=False) if c > 0]
    active_colors = [_SEV_COLORS[i] for i, c in enumerate(counts) if c > 0]

    for i, col in enumerate(active_colors):
        pie.slices[i].fillColor = col

    d.add(pie)

    # Legend
    legend = Legend()
    legend.x = int(width * 0.72)
    legend.y = int(height * 0.75)
    legend.dx = 8
    legend.dy = 8
    legend.fontName = "Helvetica"
    legend.fontSize = 7
    legend.boxAnchor = "nw"
    legend.columnMaximum = 10
    legend.strokeWidth = 0
    legend.strokeColor = colors.white
    legend.deltax = 60
    legend.deltay = 12
    legend.autoXPadding = 5
    legend.colorNamePairs = [
        (c, f"{s.capitalize()}: {n}")
        for c, s, n in zip(active_colors, active_labels, pie.data, strict=False)
    ]
    d.add(legend)
    return d


def build_pillar_bar(
    pillar_scores: dict[str, float],
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Horizontal bar chart — compliance % per pillar."""
    if not pillar_scores:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No pillar data")
        return d

    pillars = sorted(pillar_scores.keys())
    scores = [pillar_scores[p] for p in pillars]
    labels = [p.replace("_", " ").title() for p in pillars]

    d = Drawing(width, height)
    bar = HorizontalBarChart()
    bar.x = int(width * 0.30)
    bar.y = int(height * 0.10)
    bar.width = int(width * 0.60)
    bar.height = int(height * 0.80)
    bar.data = [scores]
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = 100
    bar.valueAxis.valueStep = 20
    bar.valueAxis.labels.fontSize = 7
    bar.categoryAxis.labels.fontSize = 7
    bar.categoryAxis.categoryNames = labels
    bar.categoryAxis.labels.dx = -3
    bar.groupSpacing = 5
    bar.barSpacing = 2

    for i, score in enumerate(scores):
        col = _PASS_COLOR if score >= 70 else (_NA_COLOR if score >= 40 else _FAIL_COLOR)
        bar.bars[(0, i)].fillColor = col

    d.add(bar)
    return d


def build_resource_compliance_bar(
    resource_types: list[str],
    compliance_pcts: list[float],
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Horizontal bar chart — compliance % per resource type."""
    if not resource_types:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No resource data")
        return d

    # Limit to top 10 most common types for readability
    pairs = sorted(zip(resource_types, compliance_pcts, strict=False), key=lambda x: x[1])[:10]
    rt_labels = [_short_resource_type(p[0]) for p in pairs]
    pcts = [p[1] for p in pairs]

    d = Drawing(width, height)
    bar = HorizontalBarChart()
    bar.x = int(width * 0.30)
    bar.y = int(height * 0.05)
    bar.width = int(width * 0.60)
    bar.height = int(height * 0.90)
    bar.data = [pcts]
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = 100
    bar.valueAxis.valueStep = 25
    bar.valueAxis.labels.fontSize = 7
    bar.categoryAxis.labels.fontSize = 6
    bar.categoryAxis.categoryNames = rt_labels
    bar.categoryAxis.labels.dx = -3
    bar.groupSpacing = 3
    bar.barSpacing = 1

    for i, pct in enumerate(pcts):
        col = _PASS_COLOR if pct >= 70 else (_NA_COLOR if pct >= 40 else _FAIL_COLOR)
        bar.bars[(0, i)].fillColor = col

    d.add(bar)
    return d


def build_trend_line(
    dates: list[str],
    compliance_scores: list[float],
    width: float = 14 * cm,
    height: float = 7 * cm,
) -> Drawing:
    """Line chart for compliance trend over historical assessments."""
    if len(dates) < 2:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "Insufficient history for trend")
        return d

    d = Drawing(width, height)
    lp = LinePlot()
    lp.x = int(width * 0.10)
    lp.y = int(height * 0.15)
    lp.width = int(width * 0.80)
    lp.height = int(height * 0.70)

    points = [(i, score) for i, score in enumerate(compliance_scores)]
    lp.data = [points]
    lp.lines[0].strokeColor = _TREND_LINE_COLOR
    lp.lines[0].strokeWidth = 2
    lp.xValueAxis.valueMin = 0
    lp.xValueAxis.valueMax = max(len(dates) - 1, 1)
    lp.xValueAxis.valueStep = 1
    lp.xValueAxis.labels.fontSize = 7
    lp.yValueAxis.valueMin = 0
    lp.yValueAxis.valueMax = 100
    lp.yValueAxis.valueStep = 20
    lp.yValueAxis.labels.fontSize = 7

    d.add(lp)

    # X-axis date labels
    for i, label in enumerate(dates):
        x = int(lp.x + i * lp.width / max(len(dates) - 1, 1))
        s = String(x, lp.y - 12, label, fontSize=6, textAnchor="middle")
        d.add(s)

    # Title
    d.add(
        String(
            int(width / 2),
            int(height - 8),
            "Compliance Score Trend (%)",
            fontSize=8,
            textAnchor="middle",
            fillColor=colors.darkblue,
        )
    )
    return d


def build_kpi_cards(
    cards: list[tuple[str, str, colors.Color]],
    width: float = 17 * cm,
    height: float = 3.2 * cm,
) -> Drawing:
    """Row of coloured executive KPI cards for header dashboards.

    Args:
        cards: list of (label, value, fill_color).  Maximum 6 per row.
        width:  total drawing width.
        height: drawing height.
    """
    n = len(cards)
    if n == 0:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No KPI data")
        return d

    gap = 0.25 * cm
    card_w = (width - (n + 1) * gap) / n
    pad_y = 0.15 * cm
    card_h = height - 2 * pad_y
    d = Drawing(width, height)

    for i, (label, value, fill) in enumerate(cards):
        x = gap + i * (card_w + gap)
        y = pad_y
        # Shadow layer
        d.add(
            Rect(
                x + 0.05 * cm,
                y - 0.05 * cm,
                card_w,
                card_h,
                fillColor=colors.HexColor("#BDC3C7"),
                strokeColor=None,
            )
        )
        # Card face
        d.add(Rect(x, y, card_w, card_h, fillColor=fill, strokeColor=None))
        # Value (large)
        d.add(
            String(
                x + card_w / 2,
                y + card_h * 0.42,
                str(value),
                fontSize=15,
                fontName="Helvetica-Bold",
                textAnchor="middle",
                fillColor=colors.white,
            )
        )
        # Label (small)
        d.add(
            String(
                x + card_w / 2,
                y + card_h * 0.13,
                label,
                fontSize=6.5,
                fontName="Helvetica",
                textAnchor="middle",
                fillColor=colors.white,
            )
        )
    return d


def build_risk_heatmap(
    categories: list[str],
    scores: list[float],
    width: float = 14 * cm,
    height: float = 6.5 * cm,
) -> Drawing:
    """Horizontal heat-bar chart for the Security Scorecard section.

    Colour thresholds: ≥ 90 green · ≥ 75 yellow · ≥ 50 orange · < 50 red.
    """
    if not categories:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No scorecard data")
        return d

    n = len(categories)
    label_w = width * 0.32
    bar_w = width * 0.52
    score_x = label_w + bar_w + 0.15 * cm
    row_h = (height - 0.8 * cm) / n
    gap = 0.08 * cm

    d = Drawing(width, height)

    # X-axis tick labels
    for tick in [0, 25, 50, 75, 100]:
        tx = label_w + bar_w * tick / 100
        d.add(
            String(
                tx,
                0.05 * cm,
                str(tick),
                fontSize=5.5,
                textAnchor="middle",
                fillColor=colors.HexColor("#7F8C8D"),
            )
        )

    for i, (cat, score) in enumerate(zip(categories, scores, strict=False)):
        y = height - 0.5 * cm - (i + 1) * row_h + gap
        # Category label
        d.add(
            String(
                label_w - 0.15 * cm,
                y + row_h * 0.28,
                cat,
                fontSize=7,
                textAnchor="end",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )
        # Background track
        d.add(
            Rect(
                label_w,
                y,
                bar_w,
                row_h - 2 * gap,
                fillColor=colors.HexColor("#ECF0F1"),
                strokeColor=colors.HexColor("#BDC3C7"),
                strokeWidth=0.3,
            )
        )
        # Coloured fill
        if score >= 90:
            fill = colors.HexColor("#27AE60")
        elif score >= 75:
            fill = colors.HexColor("#F1C40F")
        elif score >= 50:
            fill = colors.HexColor("#E67E22")
        else:
            fill = colors.HexColor("#E74C3C")
        fill_w = bar_w * min(score, 100.0) / 100
        if fill_w > 0:
            d.add(Rect(label_w, y, fill_w, row_h - 2 * gap, fillColor=fill, strokeColor=None))
        # Score percentage label
        d.add(
            String(
                score_x,
                y + row_h * 0.28,
                f"{score:.0f}%",
                fontSize=7,
                textAnchor="start",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )
    return d


def build_resource_group_bar(
    rg_names: list[str],
    compliance_pcts: list[float],
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Horizontal bar chart for resource-group compliance, sorted worst-first.

    Displays at most 12 resource groups.
    """
    if not rg_names:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No resource group data")
        return d

    pairs = sorted(zip(rg_names, compliance_pcts, strict=False), key=lambda x: x[1])[:12]
    labels = [p[0][:20] for p in pairs]
    pcts = [p[1] for p in pairs]

    d = Drawing(width, height)
    bar = HorizontalBarChart()
    bar.x = int(width * 0.30)
    bar.y = int(height * 0.06)
    bar.width = int(width * 0.62)
    bar.height = int(height * 0.90)
    bar.data = [pcts]
    bar.valueAxis.valueMin = 0
    bar.valueAxis.valueMax = 100
    bar.valueAxis.valueStep = 25
    bar.valueAxis.labels.fontSize = 7
    bar.categoryAxis.labels.fontSize = 6
    bar.categoryAxis.categoryNames = labels
    bar.categoryAxis.labels.dx = -3
    bar.groupSpacing = 3
    bar.barSpacing = 1

    for i, pct in enumerate(pcts):
        col = _PASS_COLOR if pct >= 90 else colors.HexColor("#F1C40F") if pct >= 50 else _FAIL_COLOR
        bar.bars[(0, i)].fillColor = col

    d.add(bar)
    return d


def build_findings_by_pillar_stacked(
    pillar_data: dict[str, dict[str, int]],
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Stacked horizontal bar — finding count per pillar, coloured by severity."""
    if not pillar_data:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No pillar data")
        return d

    _SEV_ORDER_L = ["critical", "high", "medium", "low", "informational"]
    _SEV_COLS_L = {
        "critical": colors.HexColor("#E74C3C"),
        "high": colors.HexColor("#E67E22"),
        "medium": colors.HexColor("#F1C40F"),
        "low": colors.HexColor("#3498DB"),
        "informational": colors.HexColor("#95A5A6"),
    }

    pillars = sorted(pillar_data.keys())
    n = len(pillars)
    max_tot = max((sum(v.values()) for v in pillar_data.values()), default=1) or 1

    label_w = width * 0.30
    bar_area = width * 0.52
    count_x = label_w + bar_area + 0.20 * cm
    row_h = (height - 1.10 * cm) / n
    gap = 0.09 * cm

    d = Drawing(width, height)
    d.add(
        String(
            width / 2,
            height - 0.35 * cm,
            "Findings by Pillar (Stacked by Severity)",
            fontSize=8,
            fontName="Helvetica-Bold",
            textAnchor="middle",
            fillColor=colors.HexColor("#2C3E50"),
        )
    )

    for i, pillar in enumerate(pillars):
        sev_counts = pillar_data[pillar]
        total = sum(sev_counts.values())
        y = height - 1.00 * cm - (i + 1) * row_h + gap

        d.add(
            String(
                label_w - 0.15 * cm,
                y + (row_h - gap) * 0.22,
                pillar.replace("_", " ").title()[:20],
                fontSize=6.5,
                textAnchor="end",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )
        d.add(
            Rect(
                label_w,
                y,
                bar_area,
                row_h - 2 * gap,
                fillColor=colors.HexColor("#ECF0F1"),
                strokeColor=colors.HexColor("#BDC3C7"),
                strokeWidth=0.3,
            )
        )

        x_off = 0.0
        for sev in _SEV_ORDER_L:
            cnt = sev_counts.get(sev, 0)
            if cnt == 0:
                continue
            seg_w = bar_area * cnt / max_tot
            d.add(
                Rect(
                    label_w + x_off,
                    y,
                    seg_w,
                    row_h - 2 * gap,
                    fillColor=_SEV_COLS_L[sev],
                    strokeColor=None,
                )
            )
            x_off += seg_w

        d.add(
            String(
                count_x,
                y + (row_h - gap) * 0.22,
                str(total),
                fontSize=6.5,
                textAnchor="start",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )

    leg_items = [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low")]
    for j, (lbl, sev_key) in enumerate(leg_items):
        lx = label_w + j * 2.20 * cm
        ly = height - 0.80 * cm
        d.add(Rect(lx, ly, 0.22 * cm, 0.17 * cm, fillColor=_SEV_COLS_L[sev_key], strokeColor=None))
        d.add(
            String(
                lx + 0.28 * cm,
                ly + 0.01 * cm,
                lbl,
                fontSize=5.5,
                textAnchor="start",
                fillColor=colors.HexColor("#555555"),
            )
        )

    return d


def build_top_risk_contributors(
    contributors: list[tuple[str, float, str]],
    width: float = 14 * cm,
    height: float = 7 * cm,
) -> Drawing:
    """Horizontal bar chart — top risk contributors ranked by weighted risk score.

    contributors: [(label, risk_score, worst_severity), ...] sorted descending.
    """
    if not contributors:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No risk contributor data")
        return d

    _SEV_COLS_L = {
        "critical": colors.HexColor("#E74C3C"),
        "high": colors.HexColor("#E67E22"),
        "medium": colors.HexColor("#F1C40F"),
        "low": colors.HexColor("#3498DB"),
        "informational": colors.HexColor("#95A5A6"),
    }

    items = contributors[:10]
    max_val = max((c[1] for c in items), default=1) or 1
    n = len(items)

    label_w = width * 0.38
    bar_area = width * 0.46
    score_x = label_w + bar_area + 0.15 * cm
    row_h = (height - 0.90 * cm) / n
    gap = 0.08 * cm

    d = Drawing(width, height)
    d.add(
        String(
            width / 2,
            height - 0.30 * cm,
            "Top Risk Contributors (Weighted Risk Score)",
            fontSize=8,
            fontName="Helvetica-Bold",
            textAnchor="middle",
            fillColor=colors.HexColor("#2C3E50"),
        )
    )

    for i, (label, score, worst_sev) in enumerate(items):
        y = height - 0.80 * cm - (i + 1) * row_h + gap
        bar_h = row_h - 2 * gap

        d.add(
            String(
                label_w - 0.15 * cm,
                y + bar_h * 0.22,
                label[:30],
                fontSize=6,
                textAnchor="end",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )
        d.add(
            Rect(
                label_w,
                y,
                bar_area,
                bar_h,
                fillColor=colors.HexColor("#ECF0F1"),
                strokeColor=colors.HexColor("#BDC3C7"),
                strokeWidth=0.3,
            )
        )

        fill_col = _SEV_COLS_L.get(worst_sev, colors.HexColor("#3498DB"))
        fill_w = bar_area * score / max_val
        if fill_w > 0:
            d.add(Rect(label_w, y, fill_w, bar_h, fillColor=fill_col, strokeColor=None))

        d.add(
            String(
                score_x,
                y + bar_h * 0.22,
                f"{score:.0f}",
                fontSize=6,
                textAnchor="start",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )

    return d


def build_compliance_breakdown(
    pillar_scores: dict[str, float],
    width: float = 14 * cm,
    height: float = 6.5 * cm,
) -> Drawing:
    """Compliance progress bars per pillar with 70% and 90% reference lines.

    pillar_scores: {pillar_name: compliance_pct_0_to_100}
    """
    if not pillar_scores:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No compliance data")
        return d

    pillars = sorted(pillar_scores.keys())
    n = len(pillars)
    label_w = width * 0.30
    bar_area = width * 0.52
    pct_x = label_w + bar_area + 0.20 * cm
    row_h = (height - 1.10 * cm) / n
    gap = 0.09 * cm
    ref_70 = label_w + bar_area * 0.70
    ref_90 = label_w + bar_area * 0.90

    d = Drawing(width, height)
    d.add(
        String(
            width / 2,
            height - 0.35 * cm,
            "Pillar Compliance Breakdown",
            fontSize=8,
            fontName="Helvetica-Bold",
            textAnchor="middle",
            fillColor=colors.HexColor("#2C3E50"),
        )
    )

    for i, pillar in enumerate(pillars):
        score = pillar_scores[pillar]
        y = height - 1.00 * cm - (i + 1) * row_h + gap
        bar_h = row_h - 2 * gap

        d.add(
            String(
                label_w - 0.15 * cm,
                y + bar_h * 0.22,
                pillar.replace("_", " ").title()[:20],
                fontSize=6.5,
                textAnchor="end",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )
        d.add(
            Rect(
                label_w,
                y,
                bar_area,
                bar_h,
                fillColor=colors.HexColor("#ECF0F1"),
                strokeColor=colors.HexColor("#BDC3C7"),
                strokeWidth=0.3,
            )
        )

        if score >= 90:
            fill = colors.HexColor("#27AE60")
        elif score >= 70:
            fill = colors.HexColor("#F1C40F")
        elif score >= 50:
            fill = colors.HexColor("#E67E22")
        else:
            fill = colors.HexColor("#E74C3C")

        fill_w = bar_area * min(score, 100.0) / 100
        if fill_w > 0:
            d.add(Rect(label_w, y, fill_w, bar_h, fillColor=fill, strokeColor=None))

        d.add(
            String(
                pct_x,
                y + bar_h * 0.22,
                f"{score:.1f}%",
                fontSize=6.5,
                textAnchor="start",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )

    # Reference lines across all bars
    bar_top = height - 1.00 * cm
    bar_bot = height - 1.00 * cm - n * row_h + gap
    for ref_x, ref_lbl, ref_col in [
        (ref_70, "70%", colors.HexColor("#E67E22")),
        (ref_90, "90%", colors.HexColor("#27AE60")),
    ]:
        d.add(Rect(ref_x, bar_bot, 0.6, bar_top - bar_bot, fillColor=ref_col, strokeColor=None))
        d.add(
            String(
                ref_x,
                bar_top + 0.06 * cm,
                ref_lbl,
                fontSize=5.5,
                textAnchor="middle",
                fillColor=ref_col,
            )
        )

    # Threshold legend
    for j, (lbl, col) in enumerate(
        [
            ("≥90% Excellent", colors.HexColor("#27AE60")),
            ("≥70% Good", colors.HexColor("#F1C40F")),
            ("≥50% Fair", colors.HexColor("#E67E22")),
            ("<50% Critical", colors.HexColor("#E74C3C")),
        ]
    ):
        lx = label_w + j * 2.15 * cm
        ly = height - 0.78 * cm
        d.add(Rect(lx, ly, 0.22 * cm, 0.16 * cm, fillColor=col, strokeColor=None))
        d.add(
            String(
                lx + 0.28 * cm,
                ly + 0.01 * cm,
                lbl,
                fontSize=5.0,
                textAnchor="start",
                fillColor=colors.HexColor("#555555"),
            )
        )

    return d


def build_compliance_roadmap(
    scenarios: list[tuple[str, float]],
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Vertical milestone bar chart showing compliance at each remediation stage.

    scenarios: [(label, compliance_pct_0_to_100), ...] ordered current → fully remediated.
    Bar color: first bar = score-based; projected bars = blue → teal → green.
    Dashed green line marks the 90 % enterprise target.
    Delta labels (+X.X%) appear between consecutive bars.
    """
    if not scenarios:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No roadmap data")
        return d

    n = len(scenarios)
    left_m = 1.6 * cm
    right_m = 1.9 * cm  # room for "90% target" label
    bot_m = 1.7 * cm
    top_m = 0.5 * cm

    chart_w = width - left_m - right_m
    chart_h = height - top_m - bot_m
    cx = left_m
    cy = bot_m

    bar_w = chart_w * 0.18
    gap_w = chart_w * 0.08
    side_pad = (chart_w - n * bar_w - (n - 1) * gap_w) / 2

    d = Drawing(width, height)

    # Chart title
    d.add(
        String(
            cx + chart_w / 2,
            height - 0.28 * cm,
            "Compliance Improvement Roadmap",
            fontSize=8,
            fontName="Helvetica-Bold",
            textAnchor="middle",
            fillColor=colors.HexColor("#2C3E50"),
        )
    )

    # Gridlines + Y-axis labels
    for tick in range(0, 101, 20):
        ty = cy + chart_h * tick / 100
        d.add(Rect(cx, ty, chart_w, 0.5, fillColor=colors.HexColor("#ECF0F1"), strokeColor=None))
        d.add(
            String(
                cx - 0.12 * cm,
                ty - 3,
                f"{tick}%",
                fontSize=6,
                textAnchor="end",
                fillColor=colors.HexColor("#7F8C8D"),
            )
        )

    # 90 % enterprise target — dashed green reference line
    ref_y = cy + chart_h * 0.90
    d.add(
        Line(
            cx,
            ref_y,
            cx + chart_w,
            ref_y,
            strokeColor=colors.HexColor("#27AE60"),
            strokeWidth=1.0,
            strokeDashArray=[5, 3],
        )
    )
    d.add(
        String(
            cx + chart_w + 0.12 * cm,
            ref_y - 3,
            "90% target",
            fontSize=5.5,
            textAnchor="start",
            fillColor=colors.HexColor("#27AE60"),
        )
    )

    _proj_fills = [
        colors.HexColor("#5DADE2"),  # after high fixed
        colors.HexColor("#45B39D"),  # after high+med fixed
        colors.HexColor("#27AE60"),  # after all fixed
    ]

    bar_tops: list[tuple[float, float]] = []

    for i, (label, score) in enumerate(scenarios):
        bx = cx + side_pad + i * (bar_w + gap_w)
        bh = chart_h * min(max(score, 0.0), 100.0) / 100.0

        if i == 0:
            # Current bar — color reflects actual score
            if score >= 90:
                fill = colors.HexColor("#27AE60")
            elif score >= 70:
                fill = colors.HexColor("#F1C40F")
            elif score >= 50:
                fill = colors.HexColor("#E67E22")
            else:
                fill = colors.HexColor("#E74C3C")
        else:
            fill = _proj_fills[min(i - 1, len(_proj_fills) - 1)]

        # Track (background)
        d.add(
            Rect(
                bx,
                cy,
                bar_w,
                chart_h,
                fillColor=colors.HexColor("#F2F3F4"),
                strokeColor=colors.HexColor("#D5D8DC"),
                strokeWidth=0.3,
            )
        )
        # Filled portion
        if bh > 0:
            d.add(Rect(bx, cy, bar_w, bh, fillColor=fill, strokeColor=None))

        # Score label above bar
        d.add(
            String(
                bx + bar_w / 2,
                cy + bh + 0.10 * cm,
                f"{score:.1f}%",
                fontSize=7,
                fontName="Helvetica-Bold",
                textAnchor="middle",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )

        # X-axis label
        d.add(
            String(
                bx + bar_w / 2,
                cy - 0.30 * cm,
                label,
                fontSize=6,
                textAnchor="middle",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )
        if i == 0:
            d.add(
                String(
                    bx + bar_w / 2,
                    cy - 0.48 * cm,
                    "(baseline)",
                    fontSize=5.5,
                    textAnchor="middle",
                    fillColor=colors.HexColor("#95A5A6"),
                )
            )

        bar_tops.append((bx + bar_w / 2, cy + bh))

    # Delta labels (+X.X%) between consecutive bars
    for i in range(len(bar_tops) - 1):
        x1, y1 = bar_tops[i]
        x2, y2 = bar_tops[i + 1]
        delta = scenarios[i + 1][1] - scenarios[i][1]
        if delta > 0.05:
            mid_x = (x1 + x2) / 2
            mid_y = max(y1, y2) + 0.18 * cm
            d.add(
                String(
                    mid_x,
                    mid_y,
                    f"+{delta:.1f}%",
                    fontSize=6,
                    fontName="Helvetica-Bold",
                    textAnchor="middle",
                    fillColor=colors.HexColor("#27AE60"),
                )
            )

    return d


def build_waf_benchmark_chart(
    pillar_scores: dict[str, float],
    targets: dict[str, float],
    width: float = 14 * cm,
    height: float = 8 * cm,
) -> Drawing:
    """Horizontal bullet chart — current WAF pillar score vs pillar-specific target.

    pillar_scores: {pillar_key: current_score_0_to_100}
    targets:       {pillar_key: target_score_0_to_100}
    Bar colour: green ≥ target · yellow within 10pp · orange within 20pp · red >20pp below.
    Dark-blue vertical tick marks each pillar's target score.
    Right margin shows current score (bold, coloured) and gap (+/-pp).
    """
    if not pillar_scores:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No benchmark data")
        return d

    left_m = 4.50 * cm
    right_m = 2.50 * cm
    top_m = 0.70 * cm
    bot_m = 0.80 * cm

    chart_w = width - left_m - right_m
    chart_h = height - top_m - bot_m
    cx = left_m
    cy = bot_m

    pillars = sorted(pillar_scores.keys())
    n = len(pillars)
    if n == 0:
        d = Drawing(width, height)
        _no_data_label(d, width, height, "No benchmark data")
        return d

    row_h = chart_h / n
    gap = 0.09 * cm

    d = Drawing(width, height)

    # Chart title
    d.add(
        String(
            cx + chart_w / 2,
            height - 0.28 * cm,
            "WAF Pillar Benchmark — Current vs Target",
            fontSize=8,
            fontName="Helvetica-Bold",
            textAnchor="middle",
            fillColor=colors.HexColor("#2C3E50"),
        )
    )

    # Vertical gridlines + x-axis labels
    for tick in [0, 25, 50, 75, 90, 100]:
        tx = cx + chart_w * tick / 100
        d.add(
            Line(tx, cy, tx, cy + chart_h, strokeColor=colors.HexColor("#E8EAED"), strokeWidth=0.4)
        )
        d.add(
            String(
                tx,
                cy - 0.32 * cm,
                f"{tick}%",
                fontSize=5.5,
                textAnchor="middle",
                fillColor=colors.HexColor("#7F8C8D"),
            )
        )

    for i, pillar in enumerate(reversed(pillars)):
        score = min(max(pillar_scores.get(pillar, 0.0), 0.0), 100.0)
        target = min(max(targets.get(pillar, 90.0), 0.0), 100.0)
        gap_pp = score - target

        row_y = cy + i * row_h
        bar_y = row_y + gap
        bar_h = row_h - 2 * gap

        # Alternating row tint
        d.add(
            Rect(
                cx,
                row_y,
                chart_w,
                row_h,
                fillColor=colors.HexColor("#F8F9FA" if i % 2 == 0 else "#FFFFFF"),
                strokeColor=None,
            )
        )

        # Grey track (full 0–100 scale)
        d.add(
            Rect(cx, bar_y, chart_w, bar_h, fillColor=colors.HexColor("#D5D8DC"), strokeColor=None)
        )

        # Bar fill colour — relative to target
        if gap_pp >= 0:
            bar_fill = colors.HexColor("#27AE60")  # at/above target
        elif gap_pp >= -10:
            bar_fill = colors.HexColor("#F1C40F")  # within 10pp
        elif gap_pp >= -20:
            bar_fill = colors.HexColor("#E67E22")  # within 20pp
        else:
            bar_fill = colors.HexColor("#E74C3C")  # >20pp below

        # Current score bar
        fill_w = chart_w * score / 100
        if fill_w > 0:
            d.add(Rect(cx, bar_y, fill_w, bar_h, fillColor=bar_fill, strokeColor=None))

        # Target tick (dark-blue vertical line + small square marker)
        target_x = cx + chart_w * target / 100
        d.add(
            Line(
                target_x,
                bar_y,
                target_x,
                bar_y + bar_h,
                strokeColor=colors.HexColor("#1A5276"),
                strokeWidth=2.0,
            )
        )
        marker_sz = 4
        d.add(
            Rect(
                target_x - marker_sz / 2,
                bar_y + (bar_h - marker_sz) / 2,
                marker_sz,
                marker_sz,
                fillColor=colors.HexColor("#1A5276"),
                strokeColor=None,
            )
        )

        # Pillar name label (left)
        d.add(
            String(
                cx - 0.15 * cm,
                bar_y + bar_h * 0.28,
                pillar.replace("_", " ").title(),
                fontSize=7,
                textAnchor="end",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )

        # Right-side labels: score (bold, coloured) + gap
        right_x = cx + chart_w + 0.18 * cm
        d.add(
            String(
                right_x,
                bar_y + bar_h * 0.55,
                f"{score:.1f}%",
                fontSize=7,
                fontName="Helvetica-Bold",
                textAnchor="start",
                fillColor=bar_fill,
            )
        )
        gap_str = f"+{gap_pp:.1f}pp" if gap_pp >= 0 else f"{gap_pp:.1f}pp"
        gap_col = colors.HexColor("#27AE60") if gap_pp >= 0 else colors.HexColor("#E74C3C")
        d.add(
            String(
                right_x,
                bar_y + bar_h * 0.05,
                gap_str,
                fontSize=6,
                textAnchor="start",
                fillColor=gap_col,
            )
        )

    # Legend
    leg_items = [
        (colors.HexColor("#27AE60"), "At/Above Target"),
        (colors.HexColor("#F1C40F"), "Within 10pp"),
        (colors.HexColor("#E67E22"), "Within 20pp"),
        (colors.HexColor("#E74C3C"), ">20pp Below"),
        (colors.HexColor("#1A5276"), "Target"),
    ]
    lx = cx
    ly = 0.08 * cm
    for fill_c, lbl in leg_items:
        d.add(Rect(lx, ly, 7, 6, fillColor=fill_c, strokeColor=None))
        d.add(
            String(
                lx + 9,
                ly + 0.5,
                lbl,
                fontSize=5.5,
                textAnchor="start",
                fillColor=colors.HexColor("#555555"),
            )
        )
        lx += 2.85 * cm

    return d


# ── Private helpers ────────────────────────────────────────────────────────────


def _no_data_label(d: Drawing, w: float, h: float, msg: str) -> None:
    d.add(
        String(
            int(w / 2),
            int(h / 2),
            msg,
            fontSize=9,
            textAnchor="middle",
            fillColor=colors.grey,
        )
    )


def _short_resource_type(resource_type: str) -> str:
    """Return a compact display name from an Azure resource type string.

    e.g. 'Microsoft.Storage/storageAccounts' → 'StorageAccounts'
    """
    if "/" in resource_type:
        return resource_type.split("/")[-1]
    return resource_type[:20]
