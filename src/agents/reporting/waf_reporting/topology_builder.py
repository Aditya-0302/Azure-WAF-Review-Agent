"""Architecture visualization — generates a resource topology Drawing.

Builds a grid of resource-type boxes from actual assessment_resources data.
Only resource types that exist in the assessment are shown.
No fabricated links, no synthetic resources.

Layout:
  ┌──────────────────────────────────────────────────┐
  │  Azure Resource Topology                         │
  │  Assessment ID: …  │  Subscriptions: N           │
  ├────────────┬────────────┬────────────┬──────────┤
  │ [Storage]  │ [KeyVault] │ [AppSvc]   │ [SQL DB] │
  │ Total:  5  │ Total:  2  │ Total:  3  │ Total: 2 │
  │ Findings:3 │ Findings:1 │ Findings:2 │ Finding:1│
  ├────────────┼────────────┼────────────┼──────────┤
  │ [AKS]      │ [SvcBus]   │ [VM]       │ …        │
  │ Total:  1  │ Total:  1  │ Total:  4  │          │
  │ Findings:1 │ Findings:0 │ Findings:3 │          │
  └────────────┴────────────┴────────────┴──────────┘

Color coding:
  Green   — 0 findings
  Orange  — 1+ findings, < 50% non-compliant
  Red     — ≥ 50% non-compliant
"""

from __future__ import annotations

import math

from reportlab.graphics.shapes import (
    Drawing,
    Rect,
    String,
)
from reportlab.lib import colors
from reportlab.lib.units import cm
from waf_reporting.aggregator import ResourceTypeStats

_BOX_W = 3.8 * cm
_BOX_H = 2.4 * cm
_GAP_X = 0.35 * cm
_GAP_Y = 0.40 * cm
_COLS = 4

_HEADER_H = 1.2 * cm
_FOOTER_H = 0.4 * cm
_SIDE_PAD = 0.5 * cm
_TOP_PAD = 0.6 * cm

_COLOR_PASS = colors.HexColor("#D5F5E3")  # light green
_COLOR_WARN = colors.HexColor("#FDEBD0")  # light orange
_COLOR_FAIL = colors.HexColor("#FADBD8")  # light red
_COLOR_BORDER = colors.HexColor("#95A5A6")
_COLOR_HEADER = colors.HexColor("#2C3E50")
_COLOR_TITLE = colors.HexColor("#ECF0F1")


def build_topology(
    resource_inventory: dict[str, ResourceTypeStats],
    assessment_id: str,
    subscription_count: int,
    width: float = 17 * cm,
) -> Drawing:
    """Return a Drawing that shows the resource topology from actual assessment data."""
    if not resource_inventory:
        d = Drawing(width, 4 * cm)
        d.add(
            String(
                width / 2,
                2 * cm,
                "No resources discovered in this assessment",
                fontSize=9,
                textAnchor="middle",
                fillColor=colors.grey,
            )
        )
        return d

    items = sorted(
        resource_inventory.values(),
        key=lambda r: r.total,
        reverse=True,
    )
    n = len(items)
    rows = math.ceil(n / _COLS)

    canvas_w = width
    canvas_h = _HEADER_H + _TOP_PAD + rows * _BOX_H + (rows - 1) * _GAP_Y + _FOOTER_H + _GAP_Y
    d = Drawing(canvas_w, canvas_h)

    # Header bar
    d.add(
        Rect(
            0, canvas_h - _HEADER_H, canvas_w, _HEADER_H, fillColor=_COLOR_HEADER, strokeColor=None
        )
    )
    d.add(
        String(
            _SIDE_PAD,
            canvas_h - _HEADER_H + 0.35 * cm,
            "Azure Resource Topology",
            fontSize=10,
            fontName="Helvetica-Bold",
            fillColor=_COLOR_TITLE,
        )
    )
    d.add(
        String(
            canvas_w - _SIDE_PAD,
            canvas_h - _HEADER_H + 0.35 * cm,
            f"Assessment {assessment_id[:8]}…  |  {subscription_count} subscription(s)",
            fontSize=8,
            fontName="Helvetica",
            fillColor=_COLOR_TITLE,
            textAnchor="end",
        )
    )

    # Resource boxes
    for idx, stats in enumerate(items):
        col = idx % _COLS
        row = idx // _COLS

        x = _SIDE_PAD + col * (_BOX_W + _GAP_X)
        y = canvas_h - _HEADER_H - _TOP_PAD - (row + 1) * _BOX_H - row * _GAP_Y

        # Choose fill colour
        if stats.with_findings == 0:
            fill = _COLOR_PASS
        elif stats.compliance_pct < 50:
            fill = _COLOR_FAIL
        else:
            fill = _COLOR_WARN

        # Box
        d.add(
            Rect(x, y, _BOX_W, _BOX_H, fillColor=fill, strokeColor=_COLOR_BORDER, strokeWidth=0.5)
        )

        # Resource type label (short name)
        short_name = _short_rt(stats.resource_type)
        d.add(
            String(
                x + _BOX_W / 2,
                y + _BOX_H - 0.55 * cm,
                short_name,
                fontSize=7,
                fontName="Helvetica-Bold",
                textAnchor="middle",
                fillColor=colors.HexColor("#2C3E50"),
            )
        )

        # Metrics
        d.add(
            String(
                x + 0.15 * cm,
                y + _BOX_H - 1.05 * cm,
                f"Resources: {stats.total}",
                fontSize=6.5,
                fillColor=colors.HexColor("#34495E"),
            )
        )
        d.add(
            String(
                x + 0.15 * cm,
                y + _BOX_H - 1.50 * cm,
                f"Findings:  {stats.with_findings}",
                fontSize=6.5,
                fillColor=colors.HexColor("#34495E"),
            )
        )
        pct_str = f"Compliance: {stats.compliance_pct:.0f}%"
        d.add(
            String(
                x + 0.15 * cm,
                y + _BOX_H - 1.95 * cm,
                pct_str,
                fontSize=6.5,
                fillColor=colors.HexColor("#34495E"),
            )
        )

    # Legend
    legend_y = _FOOTER_H
    _legend_box(d, _SIDE_PAD, legend_y, _COLOR_PASS, "No findings")
    _legend_box(d, _SIDE_PAD + 3.5 * cm, legend_y, _COLOR_WARN, "< 50% affected")
    _legend_box(d, _SIDE_PAD + 7.5 * cm, legend_y, _COLOR_FAIL, "≥ 50% affected")

    return d


# ── Private helpers ────────────────────────────────────────────────────────────


def _short_rt(resource_type: str) -> str:
    """Microsoft.Storage/storageAccounts → StorageAccounts."""
    if "/" in resource_type:
        tail = resource_type.split("/")[-1]
    else:
        tail = resource_type
    # Trim to fit box
    return tail[:18]


def _legend_box(
    d: Drawing,
    x: float,
    y: float,
    fill: colors.Color,
    label: str,
) -> None:
    size = 0.30 * cm
    d.add(
        Rect(
            x, y + 0.05 * cm, size, size, fillColor=fill, strokeColor=_COLOR_BORDER, strokeWidth=0.4
        )
    )
    d.add(String(x + size + 0.10 * cm, y + 0.06 * cm, label, fontSize=6.5, fillColor=colors.grey))
