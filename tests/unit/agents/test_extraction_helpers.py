"""Unit tests for ExtractionHandler helper functions.

Covers _parse_arm_id and _build_raw_properties — pure functions, no I/O.
"""

from __future__ import annotations

import pytest
from waf_extraction.handler import _build_raw_properties, _parse_arm_id

# ---------------------------------------------------------------------------
# _parse_arm_id
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseArmId:
    def test_standard_vm_resource_id(self) -> None:
        rid = (
            "/subscriptions/12345678-1234-1234-1234-123456789012"
            "/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm"
        )
        resource_type, location, resource_group = _parse_arm_id(rid)
        assert resource_type == "microsoft.compute/virtualmachines"
        assert location == ""  # not in ARM ID
        assert resource_group == "my-rg"

    def test_storage_account_resource_id(self) -> None:
        rid = (
            "/subscriptions/aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa"
            "/resourceGroups/storage-rg/providers/Microsoft.Storage/storageAccounts/myaccount"
        )
        resource_type, _, resource_group = _parse_arm_id(rid)
        assert resource_type == "microsoft.storage/storageaccounts"
        assert resource_group == "storage-rg"

    def test_aks_cluster_resource_id(self) -> None:
        rid = (
            "/subscriptions/00000000-0000-0000-0000-000000000000"
            "/resourceGroups/aks-rg/providers/Microsoft.ContainerService/managedClusters/my-aks"
        )
        resource_type, _, resource_group = _parse_arm_id(rid)
        assert resource_type == "microsoft.containerservice/managedclusters"
        assert resource_group == "aks-rg"

    def test_resource_group_name_preserved(self) -> None:
        rid = (
            "/subscriptions/00000000-0000-0000-0000-000000000000"
            "/resourceGroups/My-Special-RG/providers/Microsoft.Network/virtualNetworks/vnet1"
        )
        _, _, resource_group = _parse_arm_id(rid)
        assert resource_group == "my-special-rg"  # lowercased

    def test_missing_providers_returns_empty_type(self) -> None:
        rid = "/subscriptions/abc123/resourceGroups/my-rg"
        resource_type, _, resource_group = _parse_arm_id(rid)
        assert resource_type == ""
        assert resource_group == "my-rg"

    def test_missing_resource_groups_returns_empty_rg(self) -> None:
        rid = "/subscriptions/abc123"
        _, _, resource_group = _parse_arm_id(rid)
        assert resource_group == ""

    def test_empty_string_returns_empty_values(self) -> None:
        resource_type, location, resource_group = _parse_arm_id("")
        assert resource_type == ""
        assert location == ""
        assert resource_group == ""

    def test_location_always_empty(self) -> None:
        rid = (
            "/subscriptions/00000000-0000-0000-0000-000000000000"
            "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
        )
        _, location, _ = _parse_arm_id(rid)
        assert location == ""

    def test_sub_resource_type_ignored(self) -> None:
        """Only namespace/type captured, not child resources."""
        rid = (
            "/subscriptions/00000000-0000-0000-0000-000000000000"
            "/resourceGroups/rg/providers/Microsoft.Network"
            "/applicationGateways/ag1/backendAddressPools/pool1"
        )
        resource_type, _, _ = _parse_arm_id(rid)
        assert resource_type == "microsoft.network/applicationgateways"


# ---------------------------------------------------------------------------
# _build_raw_properties
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBuildRawProperties:
    def _full_row(self) -> dict:
        return {
            "id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "eastus",
            "resourceGroup": "rg",
            "subscriptionId": "abc",
            "tenantId": "tenant-id",
            "properties": {"hardwareProfile": {"vmSize": "Standard_D4s_v3"}},
            "tags": {"env": "prod"},
            "sku": {"name": "Standard_LRS"},
            "kind": None,
            "identity": {"type": "SystemAssigned"},
            "zones": ["1", "2"],
            "managedBy": None,
        }

    def test_all_standard_fields_included(self) -> None:
        row = self._full_row()
        result = _build_raw_properties(row)
        assert result["id"] == row["id"]
        assert result["name"] == row["name"]
        assert result["type"] == row["type"]
        assert result["location"] == row["location"]
        assert result["resourceGroup"] == row["resourceGroup"]
        assert result["subscriptionId"] == row["subscriptionId"]
        assert result["tenantId"] == row["tenantId"]

    def test_properties_nested_dict_preserved(self) -> None:
        row = self._full_row()
        result = _build_raw_properties(row)
        assert result["properties"]["hardwareProfile"]["vmSize"] == "Standard_D4s_v3"

    def test_tags_preserved(self) -> None:
        row = self._full_row()
        result = _build_raw_properties(row)
        assert result["tags"] == {"env": "prod"}

    def test_zones_preserved(self) -> None:
        row = self._full_row()
        result = _build_raw_properties(row)
        assert result["zones"] == ["1", "2"]

    def test_missing_optional_fields_default_to_none_or_empty(self) -> None:
        row = {
            "id": "/subs/abc/res/1",
            "name": "res1",
            "type": "Microsoft.Compute/virtualMachines",
        }
        result = _build_raw_properties(row)
        assert result["properties"] == {}
        assert result["tags"] == {}
        assert result["sku"] is None
        assert result["kind"] is None
        assert result["identity"] is None
        assert result["zones"] is None
        assert result["managedBy"] is None

    def test_managed_by_present_for_attached_disk(self) -> None:
        row = {
            "id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/disks/disk1",
            "name": "disk1",
            "type": "Microsoft.Compute/disks",
            "managedBy": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        }
        result = _build_raw_properties(row)
        assert result["managedBy"] == row["managedBy"]

    def test_managed_by_none_for_unattached_disk(self) -> None:
        row = {
            "id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/disks/disk2",
            "name": "disk2",
            "type": "Microsoft.Compute/disks",
            "managedBy": None,
        }
        result = _build_raw_properties(row)
        assert result["managedBy"] is None

    def test_empty_string_defaults(self) -> None:
        row: dict = {}
        result = _build_raw_properties(row)
        assert result["id"] == ""
        assert result["name"] == ""
        assert result["type"] == ""
        assert result["location"] == ""
        assert result["resourceGroup"] == ""
        assert result["subscriptionId"] == ""
        assert result["tenantId"] == ""

    def test_none_properties_replaced_with_empty_dict(self) -> None:
        row = {"properties": None}
        result = _build_raw_properties(row)
        assert result["properties"] == {}

    def test_none_tags_replaced_with_empty_dict(self) -> None:
        row = {"tags": None}
        result = _build_raw_properties(row)
        assert result["tags"] == {}
