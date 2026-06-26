"""Framework Refresher — detects when the WAF catalog may be out of date.

Microsoft updates the Well-Architected Framework periodically. This module compares
the control codes declared in framework_inventory.json against waf_controls.json to
surface additions, removals, and version changes — without ever making network calls.

The workflow:
  1. When Microsoft updates the framework, update framework_inventory.json manually
     (the source of truth for declared codes and counts).
  2. Run `python -m waf_catalog.refresher` to produce a change report.
  3. Act on: add new waf_controls.json entries, update waf_control_mapping.json, etc.

Usage:
    from waf_catalog.refresher import detect_changes, ChangeReport
    report = detect_changes()
    if report.has_changes:
        print(report.summary())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_CATALOG_DIR = Path(__file__).parent


@dataclass
class ChangeReport:
    added_codes: list[str] = field(default_factory=list)
    removed_codes: list[str] = field(default_factory=list)
    version_changed: bool = False
    previous_version: str = ""
    current_version: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.added_codes or self.removed_codes or self.version_changed)

    def summary(self) -> str:
        lines: list[str] = []
        if self.version_changed:
            lines.append(
                f"Framework version changed: {self.previous_version} → {self.current_version}"
            )
        if self.added_codes:
            lines.append(f"Added controls ({len(self.added_codes)}):")
            lines.extend(f"  + {c}" for c in sorted(self.added_codes))
        if self.removed_codes:
            lines.append(f"Removed controls ({len(self.removed_codes)}):")
            lines.extend(f"  - {c}" for c in sorted(self.removed_codes))
        return "\n".join(lines) if lines else "No changes detected."

    def to_dict(self) -> dict:
        return {
            "has_changes": self.has_changes,
            "version_changed": self.version_changed,
            "previous_version": self.previous_version,
            "current_version": self.current_version,
            "added_codes": sorted(self.added_codes),
            "removed_codes": sorted(self.removed_codes),
        }


def detect_changes() -> ChangeReport:
    """Compare framework_inventory.json against waf_controls.json and return a diff.

    framework_inventory.json is the authoritative list of what Microsoft publishes.
    waf_controls.json is what we have implemented. Anything in the inventory but not
    in controls is an addition we need to implement. Anything in controls but not in
    the inventory is a removal (the recommendation was retired or merged).
    """
    inventory_path = _CATALOG_DIR / "framework_inventory.json"
    controls_path = _CATALOG_DIR / "waf_controls.json"

    if not inventory_path.exists():
        raise FileNotFoundError(f"framework_inventory.json not found at {inventory_path}")
    if not controls_path.exists():
        raise FileNotFoundError(f"waf_controls.json not found at {controls_path}")

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    controls_raw: list[dict] = json.loads(controls_path.read_text(encoding="utf-8"))

    inventory_version: str = inventory.get("framework_version", "")
    inventory_codes: set[str] = {
        r["code"] for r in inventory.get("recommendations", [])
    }

    controls_versions: set[str] = set()
    controls_codes: set[str] = set()
    for ctrl in controls_raw:
        controls_codes.add(ctrl["code"])
        controls_versions.add(ctrl.get("version", ""))

    current_version = next(iter(controls_versions)) if len(controls_versions) == 1 else "mixed"

    added = sorted(inventory_codes - controls_codes)
    removed = sorted(controls_codes - inventory_codes)
    version_changed = bool(inventory_version and current_version and inventory_version != current_version)

    return ChangeReport(
        added_codes=added,
        removed_codes=removed,
        version_changed=version_changed,
        previous_version=current_version,
        current_version=inventory_version,
    )


if __name__ == "__main__":
    import sys

    report = detect_changes()
    print(report.summary())
    if report.has_changes:
        sys.exit(1)
