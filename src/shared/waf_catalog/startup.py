"""WAF Catalog startup validation and rule coverage reporting.

Called once at process startup (before accepting messages) by the reasoning agent.
Raises ``CatalogStartupError`` if the catalog is unusable or any active rule is
missing from the mapping — preventing the agent from silently producing findings
with empty WAF traceability.

Usage:
    catalog = WafCatalog.get_instance()
    validate_catalog_startup(catalog)                # raises on any integrity failure

    # After DB is connected:
    rule_ids = [r.rule_id for r in await rule_repo.list_active()]
    report = build_coverage_report(catalog, rule_ids)
    if not report.is_complete:
        raise CatalogStartupError(format_coverage_failure(report))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waf_catalog.catalog import WafCatalog


class CatalogStartupError(Exception):
    """Raised at process startup when the WAF catalog fails validation.

    The reasoning agent refuses to start rather than silently producing
    findings with empty waf_codes/waf_titles/microsoft_urls.
    """


@dataclass(frozen=True)
class RuleCoverageEntry:
    rule_id: str
    is_mapped: bool
    waf_codes: list[str]


@dataclass
class RuleCoverageReport:
    entries: list[RuleCoverageEntry] = field(default_factory=list)
    total_rules: int = 0
    mapped_count: int = 0
    missing_count: int = 0
    coverage_percentage: float = 100.0
    missing_rule_ids: list[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return self.missing_count == 0


def validate_catalog_startup(catalog: "WafCatalog") -> None:
    """Validate that the catalog is structurally sound and integrity-clean.

    Reuses the existing ``validate_catalog()`` from validator.py — which checks
    code format, URL presence, and mapping validity — and wraps any
    ``CatalogValidationError`` in a ``CatalogStartupError`` so callers only
    need to catch one exception type at startup.

    Additionally enforces that the mapping file is non-empty at startup: the
    reasoning agent cannot produce WAF-traceable findings with 0 mapped rules.
    (``validate_catalog`` allows empty mappings for partial/dev catalogs; this
    function is stricter because it guards production process startup.)

    Raises:
        CatalogStartupError: If any validation rule fails.
    """
    from waf_catalog.validator import CatalogValidationError, validate_catalog

    # Startup-specific guard: mapping must be non-empty.
    if not catalog.get_mapped_rule_ids():
        raise CatalogStartupError(
            "WAF catalog startup failed: waf_control_mapping.json contains 0 mappings. "
            "The file is empty or was not loaded correctly."
        )

    try:
        validate_catalog(catalog)
    except CatalogValidationError as exc:
        raise CatalogStartupError(str(exc)) from exc


def build_coverage_report(
    catalog: "WafCatalog",
    rule_ids: list[str],
) -> RuleCoverageReport:
    """Build a per-rule coverage report against the catalog mapping.

    Args:
        catalog: Loaded WafCatalog instance.
        rule_ids: All rule IDs to check (typically all active rules from DB).

    Returns:
        RuleCoverageReport with per-rule entries and summary stats.
        ``report.is_complete`` is True only when every rule_id has a mapping.
    """
    mapped_ids = catalog.get_mapped_rule_ids()
    entries: list[RuleCoverageEntry] = []

    for rule_id in sorted(rule_ids):
        codes = catalog.get_codes_for_rule(rule_id)
        entries.append(RuleCoverageEntry(
            rule_id=rule_id,
            is_mapped=rule_id in mapped_ids,
            waf_codes=codes,
        ))

    total = len(rule_ids)
    missing = [e.rule_id for e in entries if not e.is_mapped]
    mapped = total - len(missing)

    return RuleCoverageReport(
        entries=entries,
        total_rules=total,
        mapped_count=mapped,
        missing_count=len(missing),
        coverage_percentage=round(mapped / total * 100, 1) if total else 100.0,
        missing_rule_ids=sorted(missing),
    )


def format_coverage_failure(report: RuleCoverageReport) -> str:
    """Format a human-readable failure message from an incomplete coverage report."""
    lines = [
        f"Rule coverage validation failed: {report.missing_count} of {report.total_rules} "
        f"active rule(s) have no WAF catalog mapping "
        f"({report.coverage_percentage:.1f}% covered, 100% required).",
        "",
        "Missing mappings:",
    ]
    for rule_id in report.missing_rule_ids:
        lines.append(f"  MISSING  {rule_id}")
    lines.append("")
    lines.append(
        "Add each missing rule_id to src/shared/waf_catalog/waf_control_mapping.json "
        "and restart the agent."
    )
    return "\n".join(lines)
