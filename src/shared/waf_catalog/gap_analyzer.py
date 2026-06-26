"""Gap Analyzer — identifies WAF controls with no implementing rules.

A gap is a WAF control that exists in the official inventory but has no active rule
mapped to it in waf_control_mapping.json. Gaps represent areas where the assessment
engine cannot evaluate compliance and an explicit architectural decision is needed:
  - Write a new rule to implement the control, or
  - Accept the gap with a documented rationale.

Usage:
    from waf_catalog.catalog import WafCatalog
    from waf_catalog.gap_analyzer import compute_gaps

    catalog = WafCatalog.get_instance()
    report = compute_gaps(catalog, active_rule_ids={"SEC-KV-001", "REL-VM-001"})
    for g in report.unmapped_controls:
        print(g.code, g.pillar, g.title)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waf_catalog.catalog import WafCatalog, WafControl


@dataclass
class ControlGap:
    code: str
    pillar: str
    title: str
    microsoft_url: str
    reason: str = "no_implementing_rule"


@dataclass
class RuleGap:
    rule_id: str
    reason: str = "not_in_catalog_mapping"


@dataclass
class GapReport:
    """All identified gaps in the current rule set vs the WAF framework."""

    unmapped_controls: list[ControlGap]
    unmapped_rules: list[RuleGap]
    total_controls: int
    total_rules: int
    gap_percentage: float
    framework_version: str = "2024"

    def to_dict(self) -> dict:
        return {
            "framework_version": self.framework_version,
            "total_controls": self.total_controls,
            "total_rules": self.total_rules,
            "unmapped_control_count": len(self.unmapped_controls),
            "unmapped_rule_count": len(self.unmapped_rules),
            "gap_percentage": self.gap_percentage,
            "unmapped_controls": [
                {
                    "code": g.code,
                    "pillar": g.pillar,
                    "title": g.title,
                    "microsoft_url": g.microsoft_url,
                    "reason": g.reason,
                }
                for g in sorted(self.unmapped_controls, key=lambda x: x.code)
            ],
            "unmapped_rules": [
                {"rule_id": r.rule_id, "reason": r.reason}
                for r in sorted(self.unmapped_rules, key=lambda x: x.rule_id)
            ],
        }

    def write_json(self, path: str) -> None:
        import json
        from pathlib import Path
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


def compute_gaps(
    catalog: "WafCatalog",
    active_rule_ids: set[str],
) -> GapReport:
    """Identify WAF controls with no rule implementation and rules with no catalog mapping.

    Args:
        catalog: Loaded WafCatalog instance.
        active_rule_ids: All rule IDs the assessment engine knows about.
    """
    mapped_codes: set[str] = set()
    for rid in active_rule_ids:
        mapped_codes.update(catalog.get_codes_for_rule(rid))

    all_codes = catalog.get_all_codes()
    unmapped_control_codes = all_codes - mapped_codes

    unmapped_controls: list[ControlGap] = []
    for code in sorted(unmapped_control_codes):
        ctrl = catalog.get_control(code)
        if ctrl is None:
            continue
        unmapped_controls.append(ControlGap(
            code=ctrl.code,
            pillar=ctrl.pillar,
            title=ctrl.title,
            microsoft_url=ctrl.microsoft_url,
        ))

    catalog_mapped_rule_ids = catalog.get_mapped_rule_ids()
    unmapped_rule_ids = active_rule_ids - catalog_mapped_rule_ids
    unmapped_rules = [RuleGap(rule_id=rid) for rid in sorted(unmapped_rule_ids)]

    total = len(all_codes)
    gap_pct = round(len(unmapped_controls) / total * 100, 1) if total else 0.0

    return GapReport(
        unmapped_controls=unmapped_controls,
        unmapped_rules=unmapped_rules,
        total_controls=total,
        total_rules=len(active_rule_ids),
        gap_percentage=gap_pct,
    )
