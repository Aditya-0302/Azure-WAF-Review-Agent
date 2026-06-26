"""Unit tests for WafCatalog singleton and enrichment logic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from waf_catalog.catalog import WafCatalog, WafEnrichment

_CONTROLS = [
    {
        "code": "SE-07",
        "pillar": "Security",
        "title": "Protect application secrets",
        "description": "Store secrets in Key Vault.",
        "microsoft_url": "https://learn.microsoft.com/azure/well-architected/security/protect-secrets",
        "keywords": ["key vault", "secrets"],
        "applicable_resource_types": ["microsoft.keyvault/vaults"],
        "version": "2024",
        "status": "active",
    },
    {
        "code": "SE-04",
        "pillar": "Security",
        "title": "Segment networks",
        "description": "Apply NSG rules.",
        "microsoft_url": "https://learn.microsoft.com/azure/well-architected/security/network-segmentation",
        "keywords": ["NSG", "firewall"],
        "applicable_resource_types": ["microsoft.network/networksecuritygroups"],
        "version": "2024",
        "status": "active",
    },
    {
        "code": "RE-02",
        "pillar": "Reliability",
        "title": "Design for redundancy",
        "description": "Use availability zones.",
        "microsoft_url": "https://learn.microsoft.com/azure/well-architected/reliability/redundancy",
        "keywords": ["availability zones", "redundancy"],
        "applicable_resource_types": ["microsoft.compute/virtualmachines"],
        "version": "2024",
        "status": "active",
    },
]

_MAPPING = {
    "schema_version": "1.0",
    "_comment": "Test mapping",
    "SEC-KV-001": ["SE-07"],
    "SEC-KV-002": ["SE-04", "SE-07"],
    "REL-VM-001": ["RE-02"],
}


@pytest.fixture(autouse=True)
def reset_singleton():
    """Ensure singleton is cleared between tests."""
    WafCatalog.reset()
    yield
    WafCatalog.reset()


@pytest.fixture
def tmp_catalog(tmp_path: Path) -> WafCatalog:
    controls_file = tmp_path / "waf_controls.json"
    mapping_file = tmp_path / "waf_control_mapping.json"
    controls_file.write_text(json.dumps(_CONTROLS), encoding="utf-8")
    mapping_file.write_text(json.dumps(_MAPPING), encoding="utf-8")
    return WafCatalog(controls_path=controls_file, mapping_path=mapping_file)


class TestWafCatalogLoading:
    def test_loads_all_controls(self, tmp_catalog: WafCatalog) -> None:
        assert len(tmp_catalog.get_all_controls()) == 3

    def test_get_control_by_code(self, tmp_catalog: WafCatalog) -> None:
        ctrl = tmp_catalog.get_control("SE-07")
        assert ctrl is not None
        assert ctrl.title == "Protect application secrets"
        assert ctrl.pillar == "Security"

    def test_get_missing_control_returns_none(self, tmp_catalog: WafCatalog) -> None:
        assert tmp_catalog.get_control("XX-99") is None

    def test_meta_keys_stripped_from_mapping(self, tmp_catalog: WafCatalog) -> None:
        mapped = tmp_catalog.get_mapped_rule_ids()
        assert "_comment" not in mapped
        assert "schema_version" not in mapped

    def test_all_rule_ids_loaded(self, tmp_catalog: WafCatalog) -> None:
        assert tmp_catalog.get_mapped_rule_ids() == {"SEC-KV-001", "SEC-KV-002", "REL-VM-001"}


class TestWafCatalogLookup:
    def test_get_codes_for_known_rule(self, tmp_catalog: WafCatalog) -> None:
        codes = tmp_catalog.get_codes_for_rule("SEC-KV-002")
        assert sorted(codes) == ["SE-04", "SE-07"]

    def test_get_codes_for_unknown_rule(self, tmp_catalog: WafCatalog) -> None:
        assert tmp_catalog.get_codes_for_rule("NONEXISTENT") == []

    def test_get_controls_for_rule(self, tmp_catalog: WafCatalog) -> None:
        ctrls = tmp_catalog.get_controls_for_rule("SEC-KV-001")
        assert len(ctrls) == 1
        assert ctrls[0].code == "SE-07"

    def test_get_controls_for_pillar(self, tmp_catalog: WafCatalog) -> None:
        security = tmp_catalog.get_controls_for_pillar("Security")
        codes = {c.code for c in security}
        assert codes == {"SE-07", "SE-04"}

    def test_get_rules_for_code(self, tmp_catalog: WafCatalog) -> None:
        rules = tmp_catalog.get_rules_for_code("SE-07")
        assert set(rules) == {"SEC-KV-001", "SEC-KV-002"}

    def test_codes_per_pillar(self, tmp_catalog: WafCatalog) -> None:
        per_pillar = tmp_catalog.codes_per_pillar()
        assert sorted(per_pillar["Security"]) == ["SE-04", "SE-07"]
        assert per_pillar["Reliability"] == ["RE-02"]

    def test_inventory_summary(self, tmp_catalog: WafCatalog) -> None:
        summary = tmp_catalog.inventory_summary()
        assert summary["Security"] == 2
        assert summary["Reliability"] == 1
        assert summary["total"] == 3


class TestFindingEnrichment:
    def test_enrich_mapped_rule(self, tmp_catalog: WafCatalog) -> None:
        e = tmp_catalog.enrich_finding("SEC-KV-001")
        assert isinstance(e, WafEnrichment)
        assert e.waf_codes == ["SE-07"]
        assert e.waf_titles == ["Protect application secrets"]
        assert "protect-secrets" in e.microsoft_urls[0]
        assert e.is_mapped is True

    def test_enrich_multi_code_rule(self, tmp_catalog: WafCatalog) -> None:
        e = tmp_catalog.enrich_finding("SEC-KV-002")
        assert sorted(e.waf_codes) == ["SE-04", "SE-07"]
        assert len(e.pillars) == 1  # Both are Security pillar
        assert e.pillars == ["Security"]

    def test_enrich_unmapped_rule_returns_empty(self, tmp_catalog: WafCatalog) -> None:
        e = tmp_catalog.enrich_finding("NONEXISTENT-001")
        assert e.waf_codes == []
        assert e.waf_titles == []
        assert e.microsoft_urls == []
        assert e.is_mapped is False

    def test_enrich_cross_pillar_rule(self, tmp_catalog: WafCatalog) -> None:
        e = tmp_catalog.enrich_finding("REL-VM-001")
        assert e.waf_codes == ["RE-02"]
        assert e.pillars == ["Reliability"]


class TestSingleton:
    def test_get_instance_returns_same_object(self) -> None:
        a = WafCatalog.get_instance()
        b = WafCatalog.get_instance()
        assert a is b

    def test_reset_clears_singleton(self) -> None:
        a = WafCatalog.get_instance()
        WafCatalog.reset()
        b = WafCatalog.get_instance()
        assert a is not b
