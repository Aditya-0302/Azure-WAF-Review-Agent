"""Unit tests for WAF traceability matrix."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from waf_catalog.catalog import WafCatalog
from waf_catalog.traceability import build_traceability_matrix, matrix_to_dict

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
]

_MAPPING = {
    "SEC-KV-001": ["SE-07"],
    "REL-VM-001": ["RE-02"],
}

_FINDINGS = [
    {
        "id": "aaaaaaaa-0000-0000-0000-000000000001",
        "rule_id": "SEC-KV-001",
        "resource_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
        "resource_type": "microsoft.keyvault/vaults",
        "pillar": "security",
        "severity": "high",
    },
    {
        "id": "aaaaaaaa-0000-0000-0000-000000000002",
        "rule_id": "REL-VM-001",
        "resource_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        "resource_type": "microsoft.compute/virtualmachines",
        "pillar": "reliability",
        "severity": "medium",
    },
    {
        "id": "aaaaaaaa-0000-0000-0000-000000000003",
        "rule_id": "UNMAPPED-RULE-001",
        "resource_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
        "resource_type": "microsoft.storage/storageaccounts",
        "pillar": "security",
        "severity": "low",
    },
]


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


class TestBuildTraceabilityMatrix:
    def test_returns_one_entry_per_finding(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, _FINDINGS)
        assert len(matrix) == 3

    def test_mapped_finding_has_waf_codes(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, _FINDINGS)
        kv_entry = next(e for e in matrix if e.rule_id == "SEC-KV-001")
        assert kv_entry.waf_codes == ["SE-07"]
        assert kv_entry.waf_titles == ["Protect secrets"]
        assert kv_entry.is_mapped is True

    def test_unmapped_finding_is_marked(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, _FINDINGS)
        unmapped = next(e for e in matrix if e.rule_id == "UNMAPPED-RULE-001")
        assert unmapped.waf_codes == []
        assert unmapped.is_mapped is False

    def test_finding_id_preserved(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, _FINDINGS)
        ids = {e.finding_id for e in matrix}
        assert "aaaaaaaa-0000-0000-0000-000000000001" in ids

    def test_finding_id_from_alternate_key(self, catalog: WafCatalog) -> None:
        findings = [
            {
                "finding_id": "test-123",
                "rule_id": "SEC-KV-001",
                "resource_id": "r",
                "resource_type": "t",
                "pillar": "security",
                "severity": "low",
            }
        ]
        matrix = build_traceability_matrix(catalog, findings)
        assert matrix[0].finding_id == "test-123"

    def test_empty_findings_returns_empty_matrix(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, [])
        assert matrix == []


class TestMatrixToDict:
    def test_counts_are_correct(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, _FINDINGS)
        result = matrix_to_dict(matrix)
        assert result["total_findings"] == 3
        assert result["mapped_findings"] == 2
        assert result["unmapped_findings"] == 1

    def test_entries_serializable(self, catalog: WafCatalog) -> None:
        matrix = build_traceability_matrix(catalog, _FINDINGS)
        result = matrix_to_dict(matrix)
        # Should not raise.
        payload = json.dumps(result)
        assert len(payload) > 0
