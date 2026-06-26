"""Coverage analyzer — measures WAF framework coverage for the current rule set.

Usage:
    from waf_catalog.catalog import WafCatalog
    from waf_catalog.coverage import compute_coverage

    catalog = WafCatalog.get_instance()
    report = compute_coverage(
        catalog=catalog,
        rule_evaluation_types={"SEC-KV-001": "deterministic", "SEC-KV-002": "llm", ...},
    )
    print(report.overall_percentage)

Coverage classification:
  COVERED            — ≥1 deterministic or hybrid rule maps to this control.
  PARTIALLY_COVERED  — only LLM or advisor_mapped rules cover this control
                       (less reliable; dependent on external systems).
  NOT_IMPLEMENTED    — no active rule maps to this control.
  UNKNOWN            — control exists in catalog but mapping status is ambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waf_catalog.catalog import WafCatalog

_STRONG_EVAL_TYPES = frozenset({"deterministic", "hybrid"})
_WEAK_EVAL_TYPES = frozenset({"llm", "advisor_mapped"})


class CoverageStatus(StrEnum):
    COVERED = "covered"
    PARTIALLY_COVERED = "partially_covered"
    NOT_IMPLEMENTED = "not_implemented"
    UNKNOWN = "unknown"


@dataclass
class ControlCoverage:
    code: str
    pillar: str
    title: str
    microsoft_url: str
    status: CoverageStatus
    rule_ids: list[str]
    rule_count: int = field(init=False)

    def __post_init__(self) -> None:
        self.rule_count = len(self.rule_ids)


@dataclass
class PillarCoverage:
    pillar: str
    total: int
    covered: int
    partially_covered: int
    not_implemented: int
    percentage: float

    @property
    def gap_count(self) -> int:
        return self.not_implemented


@dataclass
class CoverageReport:
    controls: list[ControlCoverage]
    pillars: dict[str, PillarCoverage]
    overall_percentage: float
    total_controls: int
    covered_controls: int
    partially_covered_controls: int
    not_implemented_controls: int
    framework_version: str
    mapped_rule_count: int

    def to_dict(self) -> dict:
        return {
            "framework_version": self.framework_version,
            "overall_percentage": self.overall_percentage,
            "total_controls": self.total_controls,
            "covered_controls": self.covered_controls,
            "partially_covered_controls": self.partially_covered_controls,
            "not_implemented_controls": self.not_implemented_controls,
            "mapped_rule_count": self.mapped_rule_count,
            "pillars": {
                p: {
                    "total": pc.total,
                    "covered": pc.covered,
                    "partially_covered": pc.partially_covered,
                    "not_implemented": pc.not_implemented,
                    "percentage": pc.percentage,
                }
                for p, pc in sorted(self.pillars.items())
            },
            "controls": [
                {
                    "code": c.code,
                    "pillar": c.pillar,
                    "title": c.title,
                    "status": c.status.value,
                    "rule_ids": c.rule_ids,
                    "microsoft_url": c.microsoft_url,
                }
                for c in sorted(self.controls, key=lambda x: x.code)
            ],
        }

    def write_json(self, path: str) -> None:
        import json
        from pathlib import Path
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


def compute_coverage(
    catalog: "WafCatalog",
    rule_evaluation_types: dict[str, str],
) -> CoverageReport:
    """Compute WAF framework coverage given a mapping of rule_id → evaluation_type.

    Args:
        catalog: Loaded WafCatalog instance.
        rule_evaluation_types: {rule_id: evaluation_type} for all active rules.
            evaluation_type is one of: "deterministic", "hybrid", "llm", "advisor_mapped".
    """
    active_rule_ids = set(rule_evaluation_types.keys())

    # Invert mapping: control_code → {strong_rules, weak_rules}
    control_to_strong: dict[str, set[str]] = {c.code: set() for c in catalog.get_all_controls()}
    control_to_weak: dict[str, set[str]] = {c.code: set() for c in catalog.get_all_controls()}

    for rid in active_rule_ids:
        eval_type = rule_evaluation_types.get(rid, "")
        for code in catalog.get_codes_for_rule(rid):
            if code not in control_to_strong:
                continue
            if eval_type in _STRONG_EVAL_TYPES:
                control_to_strong[code].add(rid)
            elif eval_type in _WEAK_EVAL_TYPES:
                control_to_weak[code].add(rid)

    controls: list[ControlCoverage] = []
    pillar_stats: dict[str, dict[str, int]] = {}

    for ctrl in catalog.get_all_controls():
        strong = control_to_strong.get(ctrl.code, set())
        weak = control_to_weak.get(ctrl.code, set())
        all_rules = sorted(strong | weak)

        if strong:
            status = CoverageStatus.COVERED
        elif weak:
            status = CoverageStatus.PARTIALLY_COVERED
        else:
            status = CoverageStatus.NOT_IMPLEMENTED

        controls.append(ControlCoverage(
            code=ctrl.code,
            pillar=ctrl.pillar,
            title=ctrl.title,
            microsoft_url=ctrl.microsoft_url,
            status=status,
            rule_ids=all_rules,
        ))

        p = ctrl.pillar
        if p not in pillar_stats:
            pillar_stats[p] = {"total": 0, "covered": 0, "partial": 0, "not_impl": 0}
        pillar_stats[p]["total"] += 1
        if status == CoverageStatus.COVERED:
            pillar_stats[p]["covered"] += 1
        elif status == CoverageStatus.PARTIALLY_COVERED:
            pillar_stats[p]["partial"] += 1
        else:
            pillar_stats[p]["not_impl"] += 1

    pillar_reports: dict[str, PillarCoverage] = {}
    for pillar, stats in pillar_stats.items():
        covered_count = stats["covered"] + stats["partial"]
        total = stats["total"]
        pillar_reports[pillar] = PillarCoverage(
            pillar=pillar,
            total=total,
            covered=stats["covered"],
            partially_covered=stats["partial"],
            not_implemented=stats["not_impl"],
            percentage=round(covered_count / total * 100, 1) if total else 0.0,
        )

    total = len(controls)
    covered = sum(1 for c in controls if c.status == CoverageStatus.COVERED)
    partial = sum(1 for c in controls if c.status == CoverageStatus.PARTIALLY_COVERED)
    not_impl = sum(1 for c in controls if c.status == CoverageStatus.NOT_IMPLEMENTED)
    overall = round((covered + partial) / total * 100, 1) if total else 0.0

    return CoverageReport(
        controls=controls,
        pillars=pillar_reports,
        overall_percentage=overall,
        total_controls=total,
        covered_controls=covered,
        partially_covered_controls=partial,
        not_implemented_controls=not_impl,
        framework_version="2024",
        mapped_rule_count=len(active_rule_ids),
    )
