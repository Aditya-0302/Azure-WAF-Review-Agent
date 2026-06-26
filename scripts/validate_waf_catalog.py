#!/usr/bin/env python3
"""CI script — validate WAF catalog integrity and fail the build on any error.

Run from the repository root:
    python scripts/validate_waf_catalog.py

Exit codes:
  0  — catalog is valid
  1  — one or more validation errors found (build fails)
  2  — unexpected exception (e.g. missing file)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "shared"))

from waf_catalog.refresher import detect_changes
from waf_catalog.validator import CatalogValidationError, validate_catalog


def main() -> int:
    print("=== WAF Catalog Validation ===\n")

    write_reports = "--write-reports" in sys.argv

    # 1. Schema integrity check.
    print("Step 1 — checking catalog schema integrity...")
    try:
        result = validate_catalog()
        print(f"  OK — {len(result.warnings)} warning(s)")
        for w in result.warnings:
            print(f"  WARNING: {w}")
    except CatalogValidationError as exc:
        print(f"\n  FAIL:\n{exc}")
        return 1

    # 2. Framework freshness check.
    print("\nStep 2 — checking for framework changes...")
    try:
        change_report = detect_changes()
        if change_report.has_changes:
            print("  WARNING — framework may have changed since catalog was last updated:")
            print(change_report.summary())
        else:
            print("  OK — no framework changes detected")
    except FileNotFoundError as exc:
        print(f"  WARNING — could not run freshness check: {exc}")

    # 3. Coverage summary.
    print("\nStep 3 — computing coverage summary...")
    from waf_catalog.catalog import WafCatalog
    from waf_catalog.coverage import compute_coverage
    from waf_catalog.gap_analyzer import compute_gaps

    catalog = WafCatalog.get_instance()
    mapped_ids = catalog.get_mapped_rule_ids()
    rule_eval_types = {rid: "deterministic" for rid in mapped_ids}
    cov_report = compute_coverage(catalog, rule_eval_types)
    gap_report = compute_gaps(catalog, mapped_ids)

    print(f"  Total controls:          {cov_report.total_controls}")
    print(f"  Covered:                 {cov_report.covered_controls}")
    print(f"  Partially covered:       {cov_report.partially_covered_controls}")
    print(f"  Not implemented:         {cov_report.not_implemented_controls}")
    print(f"  Overall coverage:        {cov_report.overall_percentage}%")
    print(f"  Mapped rules:            {cov_report.mapped_rule_count}")
    print(f"  Coverage gaps:           {gap_report.gap_percentage}%")

    # 4. Optionally write report artifacts.
    if write_reports:
        import json

        catalog_dir = Path(__file__).parent.parent / "src" / "shared" / "waf_catalog"

        cov_path = catalog_dir / "coverage_report.json"
        cov_path.write_text(json.dumps(cov_report.to_dict(), indent=2), encoding="utf-8")
        print(f"\n  Written: {cov_path}")

        gap_path = catalog_dir / "gap_analysis.json"
        gap_path.write_text(json.dumps(gap_report.to_dict(), indent=2), encoding="utf-8")
        print(f"  Written: {gap_path}")

        validation_path = catalog_dir / "framework_validation_report.json"
        validation_summary = {
            "generated_at": "2026-06-22",
            "catalog_valid": True,
            "framework_version": "2024",
            "coverage_percentage": cov_report.overall_percentage,
            "total_controls": cov_report.total_controls,
            "covered_controls": cov_report.covered_controls,
            "not_implemented_controls": cov_report.not_implemented_controls,
            "mapped_rules": cov_report.mapped_rule_count,
            "gap_percentage": gap_report.gap_percentage,
            "framework_changes": change_report.has_changes if "change_report" in dir() else False,
        }
        validation_path.write_text(json.dumps(validation_summary, indent=2), encoding="utf-8")
        print(f"  Written: {validation_path}")

    print("\n=== Validation PASSED ===")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"\nUnexpected error: {exc}", file=sys.stderr)
        sys.exit(2)
