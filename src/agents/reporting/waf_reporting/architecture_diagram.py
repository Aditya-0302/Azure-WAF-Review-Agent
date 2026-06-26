"""Architecture hierarchy diagram — Subscription → Resource Group → Resource Type.

Builds an actual relationship graph from ARM resource IDs in assessment findings.
No Azure calls, no DB queries. Only resources that appear in findings are shown.

Severity coloring:
  Green  (#D5F5E3) — compliant: no findings or low/informational only
  Yellow (#FEF9C3) — medium risk: medium findings, no critical/high
  Red    (#FADBD8) — high/critical risk: at least one critical or high finding

Public API:
  build_hierarchy_diagram(findings, agg, width) → Drawing
  render_hierarchy_png(findings, agg, width, dpi) → bytes | None
  hierarchy_rows(findings) → list of (sub_display, rg, resource_type, count, worst_sev)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.units import cm
from waf_reporting.aggregator import AggregatedReport

from waf_shared.domain.models.finding import Finding

# ── Colour palette ─────────────────────────────────────────────────────────────

_C_GREEN = colors.HexColor("#D5F5E3")  # compliant / green
_C_YELLOW = colors.HexColor("#FEF9C3")  # medium risk / yellow
_C_RED = colors.HexColor("#FADBD8")  # high/critical / red
_C_BORDER = colors.HexColor("#95A5A6")
_C_HDR_BG = colors.HexColor("#2C3E50")
_C_HDR_FG = colors.HexColor("#ECF0F1")
_C_CONN = colors.HexColor("#7F8C8D")
_C_TEXT = colors.HexColor("#2C3E50")
_C_SUBTEXT = colors.HexColor("#95A5A6")

# ── Layout constants ───────────────────────────────────────────────────────────

_HEADER_H = 1.00 * cm  # title bar height
_TOP_PAD = 0.45 * cm  # gap between header and sub nodes
_SUB_W = 5.00 * cm  # subscription box width
_SUB_H = 0.85 * cm  # subscription box height
_LEVEL_GAP_1 = 1.05 * cm  # connector space: subscription → RG
_RG_W = 2.80 * cm  # resource-group box width
_RG_H = 0.85 * cm  # resource-group box height
_LEVEL_GAP_2 = 0.95 * cm  # connector space: RG → resource type
_RT_W = 2.20 * cm  # resource-type box width
_RT_H = 0.75 * cm  # resource-type box height
_BOT_PAD = 0.30 * cm  # gap above legend
_FOOTER_H = 0.65 * cm  # legend strip height
_BOT_PAD2 = 0.25 * cm  # bottom margin
_SIDE_PAD = 0.50 * cm  # left/right canvas margin
_H_GAP = 0.30 * cm  # horizontal gap between resource-type siblings
_RG_GAP = 0.48 * cm  # horizontal gap between RG slots

_MAX_RGS = 8  # max resource groups shown per subscription
_MAX_RTS = 5  # max resource types shown per RG

# Severity ordering: 0 = best, 5 = worst
_SEV_RANK: dict[str, int] = {
    "none": 0,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


# ── Internal tree nodes ────────────────────────────────────────────────────────


@dataclass
class _RTNode:
    resource_type: str
    count: int
    worst_sev: str


@dataclass
class _RGNode:
    rg_name: str
    count: int
    worst_sev: str
    resource_types: list[_RTNode] = field(default_factory=list)


@dataclass
class _SubNode:
    sub_id: str  # first 8 chars of subscription UUID
    count: int
    worst_sev: str
    resource_groups: list[_RGNode] = field(default_factory=list)


# ── ARM ID helpers ─────────────────────────────────────────────────────────────


def _parse_arm(resource_id: str) -> tuple[str, str]:
    """Extract (subscription_short_id, rg_name) from an ARM resource ID.

    /subscriptions/{uuid}/resourceGroups/{name}/providers/…
    """
    parts = resource_id.split("/")
    sub_id = "unknown"
    rg_name = "Unknown"
    for i, part in enumerate(parts):
        low = part.lower()
        if low == "subscriptions" and i + 1 < len(parts):
            sub_id = parts[i + 1][:8]
        elif low == "resourcegroups" and i + 1 < len(parts):
            rg_name = parts[i + 1]
    return sub_id, rg_name


def _worst(sev_set: set[str]) -> str:
    """Return the highest severity from a set, or 'none' if empty."""
    return max(sev_set, key=lambda s: _SEV_RANK.get(s, 0)) if sev_set else "none"


def _sev_color(worst_sev: str) -> colors.Color:
    if worst_sev in ("critical", "high"):
        return _C_RED
    if worst_sev == "medium":
        return _C_YELLOW
    return _C_GREEN


def _short(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _short_rt(rt: str) -> str:
    """Microsoft.Storage/storageAccounts → StorageAccounts (≤13 chars)."""
    name = rt.split("/")[-1] if "/" in rt else rt
    return _short(name, 13)


def _short_rg(rg: str) -> str:
    return _short(rg, 13)


def _short_sub(sub_id: str) -> str:
    return f"Sub…{sub_id[:6]}"


# ── Tree construction ──────────────────────────────────────────────────────────


def _parse_tree(findings: list[Finding]) -> list[_SubNode]:
    """Build Subscription → RG → ResourceType tree from findings list."""
    # sub_id → rg_name → resource_type → set of severity values
    tree: dict[str, dict[str, dict[str, set[str]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(set))
    )
    for f in findings:
        sub_id, rg_name = _parse_arm(f.resource_id)
        tree[sub_id][rg_name][f.resource_type].add(f.severity.value)

    sub_nodes: list[_SubNode] = []
    for sub_id in sorted(tree):
        rg_dict = tree[sub_id]
        rg_nodes: list[_RGNode] = []
        for rg_name, rt_dict in rg_dict.items():
            rt_nodes: list[_RTNode] = []
            all_sevs: set[str] = set()
            for rt, sevs in rt_dict.items():
                all_sevs |= sevs
                rt_nodes.append(_RTNode(rt, len(sevs), _worst(sevs)))
            rt_nodes.sort(key=lambda r: (-_SEV_RANK.get(r.worst_sev, 0), -r.count))
            rg_count = sum(r.count for r in rt_nodes)
            rg_nodes.append(
                _RGNode(
                    rg_name=rg_name,
                    count=rg_count,
                    worst_sev=_worst(all_sevs),
                    resource_types=rt_nodes[:_MAX_RTS],
                )
            )
        rg_nodes.sort(key=lambda r: (-_SEV_RANK.get(r.worst_sev, 0), -r.count))
        rg_nodes = rg_nodes[:_MAX_RGS]
        all_sub_sevs = {rt.worst_sev for rg in rg_nodes for rt in rg.resource_types}
        sub_count = sum(rg.count for rg in rg_nodes)
        sub_nodes.append(
            _SubNode(
                sub_id=sub_id,
                count=sub_count,
                worst_sev=_worst(all_sub_sevs),
                resource_groups=rg_nodes,
            )
        )
    return sub_nodes


# ── Drawing primitives ─────────────────────────────────────────────────────────


def _box(
    d: Drawing,
    x: float,
    y: float,
    w: float,
    h: float,
    fill: colors.Color,
    label: str,
    sublabel: str = "",
    fsize: float = 7.0,
) -> None:
    """Draw a filled rect with centred label and optional small sublabel."""
    d.add(Rect(x, y, w, h, fillColor=fill, strokeColor=_C_BORDER, strokeWidth=0.6))
    lx = x + w / 2
    # Shift label up slightly when sublabel is present to keep them balanced
    ly = y + h / 2 + (fsize * 0.2 if sublabel else 0)
    d.add(
        String(
            lx,
            ly,
            label,
            fontSize=fsize,
            fontName="Helvetica-Bold",
            textAnchor="middle",
            fillColor=_C_TEXT,
        )
    )
    if sublabel:
        d.add(
            String(
                lx,
                y + h / 2 - fsize * 0.9,
                sublabel,
                fontSize=max(4.5, fsize - 1.5),
                fontName="Helvetica",
                textAnchor="middle",
                fillColor=_C_SUBTEXT,
            )
        )


def _hline(d: Drawing, x1: float, x2: float, y: float) -> None:
    d.add(Line(x1, y, x2, y, strokeColor=_C_CONN, strokeWidth=0.5))


def _vline(d: Drawing, x: float, y1: float, y2: float) -> None:
    d.add(Line(x, y1, x, y2, strokeColor=_C_CONN, strokeWidth=0.5))


def _legend_item(d: Drawing, x: float, y: float, fill: colors.Color, label: str) -> None:
    sz = 0.28 * cm
    d.add(Rect(x, y + 0.04 * cm, sz, sz, fillColor=fill, strokeColor=_C_BORDER, strokeWidth=0.4))
    d.add(
        String(
            x + sz + 0.10 * cm,
            y + 0.05 * cm,
            label,
            fontSize=6.5,
            fillColor=colors.HexColor("#555555"),
        )
    )


# ── Public diagram builder ─────────────────────────────────────────────────────


def build_hierarchy_diagram(
    findings: list[Finding],
    agg: AggregatedReport,
    width: float = 17 * cm,
) -> Drawing:
    """Return a ReportLab Drawing of the Subscription → RG → ResourceType tree.

    Coloring is severity-driven: red = critical/high, yellow = medium, green = low/none.
    All data is derived from findings; no Azure calls are made.
    """
    sub_nodes = _parse_tree(findings)

    if not sub_nodes:
        d = Drawing(width, 3 * cm)
        d.add(
            String(
                width / 2,
                1.5 * cm,
                "No resource hierarchy data available from findings.",
                fontSize=9,
                textAnchor="middle",
                fillColor=colors.grey,
            )
        )
        return d

    all_rgs: list[_RGNode] = [rg for sub in sub_nodes for rg in sub.resource_groups]
    has_rts = any(rg.resource_types for rg in all_rgs)

    # ── Y positions (reportlab: y=0 at bottom, increases upward) ──────────────
    y_leg = _BOT_PAD2
    y_rt_b = y_leg + _FOOTER_H + _BOT_PAD
    y_rt_t = y_rt_b + _RT_H
    y_rg_b = (y_rt_t + _LEVEL_GAP_2) if has_rts else (y_leg + _FOOTER_H + _BOT_PAD)
    y_rg_t = y_rg_b + _RG_H
    y_sub_b = y_rg_t + _LEVEL_GAP_1
    y_sub_t = y_sub_b + _SUB_H
    y_hdr_b = y_sub_t + _TOP_PAD
    canvas_h = y_hdr_b + _HEADER_H

    # Connector bus Y midpoints
    y_bus_srg = (y_sub_b + y_rg_t) / 2
    y_bus_rrt = (y_rg_b + y_rt_t) / 2 if has_rts else 0.0

    d = Drawing(width, canvas_h)

    # ── Header bar ─────────────────────────────────────────────────────────────
    d.add(Rect(0, y_hdr_b, width, _HEADER_H, fillColor=_C_HDR_BG, strokeColor=None))
    d.add(
        String(
            _SIDE_PAD,
            y_hdr_b + 0.33 * cm,
            "Azure Architecture Hierarchy  —  Subscription  →  Resource Group  →  Resource Type",
            fontSize=7.5,
            fontName="Helvetica-Bold",
            fillColor=_C_HDR_FG,
        )
    )
    d.add(
        String(
            width - _SIDE_PAD,
            y_hdr_b + 0.33 * cm,
            f"Assessment {str(agg.assessment_id)[:8]}…",
            fontSize=7,
            fontName="Helvetica",
            fillColor=_C_HDR_FG,
            textAnchor="end",
        )
    )

    # ── Horizontal layout ──────────────────────────────────────────────────────
    usable = width - 2 * _SIDE_PAD
    n_rg = len(all_rgs)

    # Ideal slot width for each RG = room needed by its RT children
    ideal: list[float] = []
    for rg in all_rgs:
        n = len(rg.resource_types)
        slot = max(_RG_W, n * _RT_W + max(0, n - 1) * _H_GAP) if n > 0 else _RG_W
        ideal.append(slot)

    total_ideal = sum(ideal) + max(0, n_rg - 1) * _RG_GAP
    if total_ideal > usable and total_ideal > 0:
        sc = usable / total_ideal
        slots = [w * sc for w in ideal]
        eff_rt = _RT_W * sc
        eff_rg = _RG_W * sc
        eff_h = _H_GAP * sc
        eff_rg_gap = _RG_GAP * sc
    else:
        sc = 1.0
        slots = list(ideal)
        eff_rt = _RT_W
        eff_rg = _RG_W
        eff_h = _H_GAP
        eff_rg_gap = _RG_GAP

    total_used = sum(slots) + max(0, n_rg - 1) * eff_rg_gap
    x_start = _SIDE_PAD + (usable - total_used) / 2

    # Compute RG centre X and each RG's RT centre Xs
    rg_cx: list[float] = []
    rg_rt_cx: list[list[float]] = []
    x = x_start
    for rg, slot in zip(all_rgs, slots, strict=False):
        cx = x + slot / 2
        rg_cx.append(cx)
        n = len(rg.resource_types)
        if n == 0:
            rg_rt_cx.append([])
        elif n == 1:
            rg_rt_cx.append([cx])
        else:
            rt_total = n * eff_rt + (n - 1) * eff_h
            rt0 = cx - rt_total / 2
            rg_rt_cx.append([rt0 + j * (eff_rt + eff_h) + eff_rt / 2 for j in range(n)])
        x += slot + eff_rg_gap

    # Map each subscription's RGs to their computed positions
    sub_groups: list[list[tuple[_RGNode, float, list[float]]]] = []
    gi = 0
    for sub in sub_nodes:
        grp: list[tuple[_RGNode, float, list[float]]] = []
        for rg in sub.resource_groups:
            grp.append((rg, rg_cx[gi], rg_rt_cx[gi]))
            gi += 1
        sub_groups.append(grp)

    # ── Connectors (drawn first so nodes render on top) ────────────────────────

    # RG → RT connectors
    if has_rts:
        for rg, cx, rt_cxs in zip(all_rgs, rg_cx, rg_rt_cx, strict=False):
            if not rt_cxs:
                continue
            _vline(d, cx, y_rg_b, y_bus_rrt)
            if len(rt_cxs) > 1:
                _hline(d, min(rt_cxs), max(rt_cxs), y_bus_rrt)
            for rtcx in rt_cxs:
                _vline(d, rtcx, y_bus_rrt, y_rt_t)

    # Sub → RG connectors
    for sub, grp in zip(sub_nodes, sub_groups, strict=False):
        if not grp:
            continue
        rg_centers = [g[1] for g in grp]
        sub_cx = (min(rg_centers) + max(rg_centers)) / 2
        _vline(d, sub_cx, y_sub_b, y_bus_srg)
        if len(rg_centers) > 1:
            _hline(d, min(rg_centers), max(rg_centers), y_bus_srg)
        for rcx in rg_centers:
            _vline(d, rcx, y_bus_srg, y_rg_t)

    # ── RT nodes ───────────────────────────────────────────────────────────────
    if has_rts:
        for rg, cx, rt_cxs in zip(all_rgs, rg_cx, rg_rt_cx, strict=False):
            for rt_node, rtcx in zip(rg.resource_types, rt_cxs, strict=False):
                _box(
                    d,
                    rtcx - eff_rt / 2,
                    y_rt_b,
                    eff_rt,
                    _RT_H,
                    _sev_color(rt_node.worst_sev),
                    _short_rt(rt_node.resource_type),
                    f"{rt_node.count} finding(s)",
                    fsize=max(4.5, 6.5 * sc),
                )

    # ── RG nodes ───────────────────────────────────────────────────────────────
    for rg, cx in zip(all_rgs, rg_cx, strict=False):
        _box(
            d,
            cx - eff_rg / 2,
            y_rg_b,
            eff_rg,
            _RG_H,
            _sev_color(rg.worst_sev),
            _short_rg(rg.rg_name),
            f"{rg.count} finding(s)",
            fsize=max(4.5, 6.5 * sc),
        )

    # ── Subscription nodes ─────────────────────────────────────────────────────
    for sub, grp in zip(sub_nodes, sub_groups, strict=False):
        if not grp:
            continue
        rg_centers = [g[1] for g in grp]
        sub_cx = (min(rg_centers) + max(rg_centers)) / 2
        _box(
            d,
            sub_cx - _SUB_W / 2,
            y_sub_b,
            _SUB_W,
            _SUB_H,
            _sev_color(sub.worst_sev),
            _short_sub(sub.sub_id),
            f"{sub.count} finding(s)",
            fsize=7.5,
        )

    # ── Legend ─────────────────────────────────────────────────────────────────
    _legend_item(d, _SIDE_PAD, y_leg, _C_GREEN, "Compliant / Low risk")
    _legend_item(d, _SIDE_PAD + 4.5 * cm, y_leg, _C_YELLOW, "Medium risk")
    _legend_item(d, _SIDE_PAD + 8.5 * cm, y_leg, _C_RED, "High / Critical risk")

    return d


# ── PNG export ─────────────────────────────────────────────────────────────────


def render_hierarchy_png(
    findings: list[Finding],
    agg: AggregatedReport,
    width: float = 24 * cm,
    dpi: int = 150,
) -> bytes | None:
    """Render the hierarchy diagram to PNG bytes.

    Returns None if renderPM is unavailable (Pillow not installed).
    The caller should always handle the None case.
    """
    try:
        from reportlab.graphics import renderPM  # noqa: PLC0415
    except ImportError:
        return None

    diagram = build_hierarchy_diagram(findings, agg, width=width)
    try:
        return renderPM.drawToString(diagram, fmt="PNG", dpi=dpi)
    except Exception:
        return None


# ── Text fallback rows ─────────────────────────────────────────────────────────


def hierarchy_rows(
    findings: list[Finding],
) -> list[tuple[str, str, str, int, str]]:
    """Return flat rows of (sub_display, rg_name, resource_type, count, worst_sev).

    Used by the Excel sheet as a text fallback when PNG rendering is unavailable.
    Rows are sorted: worst subscription severity first, then worst RG, then worst RT.
    """
    rows: list[tuple[str, str, str, int, str]] = []
    for sub in _parse_tree(findings):
        sub_disp = _short_sub(sub.sub_id)
        for rg in sub.resource_groups:
            if rg.resource_types:
                for rt in rg.resource_types:
                    rows.append((sub_disp, rg.rg_name, rt.resource_type, rt.count, rt.worst_sev))
            else:
                rows.append((sub_disp, rg.rg_name, "—", rg.count, rg.worst_sev))
    return rows
