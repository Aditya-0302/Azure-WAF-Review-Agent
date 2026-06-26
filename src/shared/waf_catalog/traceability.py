"""Traceability Matrix — links findings to rules to WAF controls to Microsoft guidance.

Each TraceabilityEntry is one row in the matrix:
  finding_id → rule_id → waf_codes → microsoft_urls

The matrix is intended for governance reports and audit trails.

Usage:
    from waf_catalog.catalog import WafCatalog
    from waf_catalog.traceability import build_traceability_matrix

    catalog = WafCatalog.get_instance()
    findings = [{"id": "...", "rule_id": "SEC-KV-001", "resource_id": "...", ...}]
    matrix = build_traceability_matrix(catalog, findings)
    for entry in matrix:
        print(entry.finding_id, entry.waf_codes, entry.microsoft_urls)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from waf_catalog.catalog import WafCatalog


@dataclass
class TraceabilityEntry:
    finding_id: str
    rule_id: str
    resource_id: str
    resource_type: str
    pillar: str
    severity: str
    waf_codes: list[str]
    waf_titles: list[str]
    microsoft_urls: list[str]
    waf_pillars: list[str]
    is_mapped: bool

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "pillar": self.pillar,
            "severity": self.severity,
            "waf_codes": self.waf_codes,
            "waf_titles": self.waf_titles,
            "microsoft_urls": self.microsoft_urls,
            "waf_pillars": self.waf_pillars,
            "is_mapped": self.is_mapped,
        }


def build_traceability_matrix(
    catalog: WafCatalog,
    findings: list[dict[str, Any]],
) -> list[TraceabilityEntry]:
    """Build a traceability matrix from a list of finding dicts.

    Each finding dict must have at minimum:
      - id (or finding_id)
      - rule_id
      - resource_id
      - resource_type
      - pillar (from finding, not WAF pillar)
      - severity
    """
    matrix: list[TraceabilityEntry] = []
    for f in findings:
        finding_id = str(f.get("id") or f.get("finding_id", "unknown"))
        rule_id = str(f.get("rule_id", ""))
        enrichment = catalog.enrich_finding(rule_id)
        matrix.append(
            TraceabilityEntry(
                finding_id=finding_id,
                rule_id=rule_id,
                resource_id=str(f.get("resource_id", "")),
                resource_type=str(f.get("resource_type", "")),
                pillar=str(f.get("pillar", "")),
                severity=str(f.get("severity", "")),
                waf_codes=enrichment.waf_codes,
                waf_titles=enrichment.waf_titles,
                microsoft_urls=enrichment.microsoft_urls,
                waf_pillars=enrichment.pillars,
                is_mapped=enrichment.is_mapped,
            )
        )
    return matrix


def matrix_to_dict(matrix: list[TraceabilityEntry]) -> dict:
    """Serialize the full matrix to a JSON-compatible dict for reporting."""
    unmapped = [e for e in matrix if not e.is_mapped]
    return {
        "total_findings": len(matrix),
        "mapped_findings": len(matrix) - len(unmapped),
        "unmapped_findings": len(unmapped),
        "entries": [e.to_dict() for e in matrix],
    }
