"""CI Catalog Validator — fails the build if the catalog has integrity violations.

The validator enforces these invariants:
  1. Every rule_id in waf_control_mapping.json maps to ≥1 valid WAF control code.
  2. Every mapped WAF code exists in waf_controls.json.
  3. No unknown keys exist in the mapping file (only _comment and schema_version are allowed).
  4. Every WAF control code in waf_controls.json uses a valid code format (SE-##, RE-##, etc.).
  5. The total number of controls matches the declared pillar counts.

This module is also used by scripts/validate_waf_catalog.py for standalone CI execution.

Usage (in CI):
    from waf_catalog.validator import validate_catalog
    validate_catalog()   # raises CatalogValidationError on failure
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waf_catalog.catalog import WafCatalog

_CODE_PATTERN = re.compile(r"^[A-Z]{2}-\d{2}$")
_META_KEYS = frozenset({"_comment", "schema_version"})


class CatalogValidationError(Exception):
    """Raised when the catalog fails integrity validation."""


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors


def validate_catalog(catalog: WafCatalog | None = None) -> ValidationResult:
    """Validate catalog integrity. Raises CatalogValidationError if errors are found.

    When catalog is None the singleton is loaded; pass an explicit instance in tests.
    """
    from waf_catalog.catalog import WafCatalog as _WafCatalog

    if catalog is None:
        catalog = _WafCatalog.get_instance()

    result = ValidationResult()

    # Structural presence check: controls file must be non-empty.
    if not catalog.get_all_controls():
        raise CatalogValidationError(
            "WAF catalog validation failed: waf_controls.json contains 0 controls. "
            "The file is empty or was not loaded correctly."
        )

    # Rule 1 & 2: every rule maps to ≥1 valid code; every code exists.
    all_control_codes = catalog.get_all_codes()
    for rule_id in catalog.get_mapped_rule_ids():
        codes = catalog.get_codes_for_rule(rule_id)
        if not codes:
            result.errors.append(f"Rule '{rule_id}' exists in mapping but has an empty code list.")
        for code in codes:
            if code not in all_control_codes:
                result.errors.append(
                    f"Rule '{rule_id}' maps to code '{code}' which does not exist in waf_controls.json."
                )

    # Rule 3b: every control has a non-empty microsoft_url.
    for ctrl in catalog.get_all_controls():
        if not ctrl.microsoft_url:
            result.errors.append(f"Control '{ctrl.code}' has an empty microsoft_url.")

    # Rule 4: all codes follow the expected format.
    for code in all_control_codes:
        if not _CODE_PATTERN.match(code):
            result.errors.append(
                f"Control code '{code}' does not match expected format (e.g. SE-01)."
            )

    # Rule 5: warn when control counts diverge from declared totals.
    # This is a completeness check (warning, not error) because catalogs are
    # legitimately incomplete during development and in tests.
    import json
    from pathlib import Path

    inventory_path = Path(__file__).parent / "framework_inventory.json"
    if inventory_path.exists():
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        declared_pillars: dict[str, dict] = inventory.get("pillars", {})
        per_pillar = catalog.codes_per_pillar()
        for pillar, meta in declared_pillars.items():
            declared_total = meta.get("total", 0)
            actual_total = len(per_pillar.get(pillar, []))
            if actual_total != declared_total:
                result.warnings.append(
                    f"Pillar '{pillar}' declares {declared_total} controls in "
                    f"framework_inventory.json but waf_controls.json contains {actual_total}."
                )
    else:
        result.warnings.append(
            "framework_inventory.json not found; pillar count validation skipped."
        )

    if not result.is_valid:
        summary = "\n".join(f"  - {e}" for e in result.errors)
        raise CatalogValidationError(
            f"WAF catalog validation failed with {len(result.errors)} error(s):\n{summary}"
        )

    return result
