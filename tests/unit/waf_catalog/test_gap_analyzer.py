"""Unit tests for WAF gap analyzer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from waf_catalog.catalog import WafCatalog
from waf_catalog.gap_analyzer import compute_gaps

_CONTROLS = [
    {
        "code": "SE-07",
        "pillar": "Security",
        "title": "Protect secrets",
        "description": ".",
        "microsoft_url": "https://example.com/SE-07",
        "keywords": [],
        "applicable_resource_types": ["*"],
        "version": "2024",
        "status": "active",
    },
    {
        "code": "RE-02",
        "pillar": "Reliability",
        "title": "Design for redundancy",
        "description": ".",
        "microsoft_url": "https://example.com/RE-02",
        "keywords": [],
        "applicable_resource_types": ["*"],
        "version": "2024",
        "status": "active",
    },
    {
        "code": "CO-06",
        "pillar": "Cost Optimization",
        "title": "Rightsize assets",
        "description": ".",
        "microsoft_url": "https://example.com/CO-06",
        "keywords": [],
        "applicable_resource_types": ["*"],
        "version": "2024",
        "status": "active",
    },
]

_MAPPING = {
    "SEC-KV-001": ["SE-07"],
    "REL-VM-001": ["RE-02"],
}


@pytest.fixture(autouse=True)
def reset_singleton():
    WafCatalog.reset()
    yield
    WafCatalog.reset()


@pytest.fixture
def catalog(tmp_path: Path) -> WafCatalog:
    (tmp_path / "waf_controls.json").write_text(json.dumps(_CONTROLS), encoding="utf-8")
    (tmp_path / "waf_control_mapping.json").write_text(json.dumps(_MAPPING), encoding="utf-8")
    return WafCatalog(
        controls_path=tmp_path / "waf_controls.json",
        mapping_path=tmp_path / "waf_control_mapping.json",
    )


class TestComputeGaps:
    def test_unmapped_control_appears_as_gap(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, {"SEC-KV-001", "REL-VM-001"})
        gap_codes = {g.code for g in report.unmapped_controls}
        assert "CO-06" in gap_codes

    def test_mapped_control_not_in_gaps(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, {"SEC-KV-001"})
        gap_codes = {g.code for g in report.unmapped_controls}
        assert "SE-07" not in gap_codes

    def test_all_controls_are_gaps_when_no_rules(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, set())
        assert len(report.unmapped_controls) == 3

    def test_no_gaps_when_all_covered(self, catalog: WafCatalog) -> None:
        # Add a rule that covers CO-06.
        extended_catalog_controls = _CONTROLS
        extended_mapping = dict(_MAPPING)
        extended_mapping["CST-VM-001"] = ["CO-06"]

        import json as _json
        import tempfile
        from pathlib import Path as _Path

        with tempfile.TemporaryDirectory() as td:
            cp = _Path(td) / "waf_controls.json"
            mp = _Path(td) / "waf_control_mapping.json"
            cp.write_text(_json.dumps(extended_catalog_controls), encoding="utf-8")
            mp.write_text(_json.dumps(extended_mapping), encoding="utf-8")
            full_catalog = WafCatalog(controls_path=cp, mapping_path=mp)

        report = compute_gaps(full_catalog, {"SEC-KV-001", "REL-VM-001", "CST-VM-001"})
        assert report.unmapped_controls == []

    def test_unmapped_rule_detected(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, {"SEC-KV-001", "UNKNOWN-RULE-001"})
        unmapped_ids = {r.rule_id for r in report.unmapped_rules}
        assert "UNKNOWN-RULE-001" in unmapped_ids

    def test_all_catalog_rules_have_no_unmapped_rules(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, catalog.get_mapped_rule_ids())
        assert report.unmapped_rules == []

    def test_gap_percentage(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, {"SEC-KV-001", "REL-VM-001"})
        # CO-06 is the only gap — 1/3 = 33.3%
        assert report.gap_percentage == pytest.approx(33.3, abs=0.1)

    def test_to_dict_structure(self, catalog: WafCatalog) -> None:
        report = compute_gaps(catalog, set())
        d = report.to_dict()
        assert "unmapped_controls" in d
        assert "unmapped_rules" in d
        assert isinstance(d["unmapped_controls"], list)

    def test_write_json(self, catalog: WafCatalog, tmp_path: Path) -> None:
        report = compute_gaps(catalog, set())
        out = tmp_path / "gaps.json"
        report.write_json(str(out))
        loaded = json.loads(out.read_text())
        assert loaded["total_controls"] == 3
