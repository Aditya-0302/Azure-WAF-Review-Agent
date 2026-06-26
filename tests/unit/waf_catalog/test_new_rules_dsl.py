"""Unit tests for Phase 3 / Phase 4 / Phase 5 WAF rule DSL definitions.

Each new rule's condition_dsl is evaluated directly with the DSL evaluator
against hand-crafted resource payloads to verify:
  - The rule fires (True) when the non-compliant condition is present.
  - The rule does NOT fire (False) when the resource is compliant.

Tests follow the same pattern as tests/unit/agents/test_dsl_evaluator.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

# ── Path bootstrap (mirrors scripts/seed_rules.py) ───────────────────────────
_ROOT = Path(__file__).resolve().parents[3]
for _pkg in ["src/shared", "src/agents/reasoning"]:
    _p = _ROOT / _pkg
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from waf_reasoning.dsl_evaluator import evaluate_condition  # noqa: E402
from waf_catalog.rule_definitions import (  # noqa: E402
    SEC_CR_001, SEC_DEF_001, SEC_NET_004,
    REL_AGW_002, REL_SB_001, REL_ASR_001,
    REL_STOR_004, REL_LB_002, REL_COSMOS_001, REL_AKS_001, REL_APP_004,
    REL_EH_001, REL_MYSQL_001, REL_POSTGRES_001, REL_REDIS_001, REL_AGW_003,
    OPS_DIAG_001, OPS_SLOT_001, OPS_MON_001,
    PER_ALERT_001,
    CST_BUDGET_001, CST_COST_TAG_001,
    CST_STOR_003, CST_APP_001, CST_SNAP_001, CST_NIC_001, CST_LOG_001,
    CST_SCALE_001, CST_PREM_001, CST_AKS_001, CST_AGW_002, CST_GW_001,
    CST_SQL_002, CST_COSMOS_001,
    OPS_AKS_001, OPS_AKS_002, OPS_NSG_001, OPS_COSMOS_001, OPS_STOR_001,
    OPS_VMSS_001, OPS_REDIS_001, OPS_APP_003, OPS_MYSQL_001, OPS_POSTGRES_001,
    OPS_ACT_001, OPS_SQL_003,
    PER_VM_004, PER_DISK_001, PER_APP_004, PER_APP_005, PER_SQL_002,
    PER_REDIS_001, PER_LB_001, PER_AGW_001, PER_CDN_002, PER_SQL_003,
    PER_COSMOS_001, PER_AKS_001,
    # Phase 8 — cross-pillar resource coverage expansion
    SEC_KV_006, SEC_KV_007,
    SEC_AFW_001,
    SEC_CA_001,
    SEC_SQLMI_001, SEC_SQLMI_002,
    SEC_EG_001, SEC_EG_002,
    SEC_APP_005, SEC_APP_006, SEC_APP_007,
    SEC_VM_004,
    SEC_AKS_001, SEC_AKS_002,
    REL_KV_001,
    REL_VNET_001,
    REL_AFW_001,
    REL_CA_001,
    REL_AVSET_001, REL_AVSET_002,
    REL_SQLMI_001,
    OPS_VNET_001,
    OPS_CA_001,
    OPS_AI_001,
    OPS_AG_001,
    CST_AI_001,
)


def _eval(condition: dict, resource: dict) -> bool:
    """Thin wrapper matching the pattern in test_dsl_evaluator.py."""
    return evaluate_condition("test-rule", condition, resource)


# ===========================================================================
# Security Rules
# ===========================================================================

@pytest.mark.unit
class TestSecCr001:
    """SEC-CR-001 — Container Registry content trust disabled."""

    _dsl = SEC_CR_001["condition_dsl"]

    def test_fires_when_trust_policy_null(self) -> None:
        resource = {"properties": {"policies": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_trust_policy_status_disabled(self) -> None:
        resource = {"properties": {"policies": {"trustPolicy": {"status": "disabled"}}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_trust_policy_status_not_enabled(self) -> None:
        resource = {"properties": {"policies": {"trustPolicy": {"status": "notset"}}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_enabled(self) -> None:
        resource = {"properties": {"policies": {"trustPolicy": {"status": "enabled"}}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_CR_001["rule_id"] == "SEC-CR-001"
        assert SEC_CR_001["pillar"] == "security"
        assert "microsoft.containerregistry/registries" in SEC_CR_001["resource_types"]
        assert SEC_CR_001["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestSecDef001:
    """SEC-DEF-001 — Defender plan on Free tier."""

    _dsl = SEC_DEF_001["condition_dsl"]

    def test_fires_when_free_tier(self) -> None:
        resource = {"properties": {"pricingTier": "Free"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard(self) -> None:
        resource = {"properties": {"pricingTier": "Standard"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_DEF_001["rule_id"] == "SEC-DEF-001"
        assert SEC_DEF_001["evaluation_type"] == "deterministic"
        assert "microsoft.security/pricings" in SEC_DEF_001["resource_types"]


@pytest.mark.unit
class TestSecNet004:
    """SEC-NET-004 — App Service missing VNet integration."""

    _dsl = SEC_NET_004["condition_dsl"]

    def test_fires_when_subnet_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_property_missing(self) -> None:
        resource = {}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_subnet_set(self) -> None:
        resource = {
            "properties": {
                "virtualNetworkSubnetId": (
                    "/subscriptions/x/resourceGroups/y/providers/"
                    "Microsoft.Network/virtualNetworks/vnet1/subnets/default"
                )
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_NET_004["rule_id"] == "SEC-NET-004"
        assert "microsoft.web/sites" in SEC_NET_004["resource_types"]


# ===========================================================================
# Reliability Rules
# ===========================================================================

@pytest.mark.unit
class TestRelAgw002:
    """REL-AGW-002 — Application Gateway no custom health probes."""

    _dsl = REL_AGW_002["condition_dsl"]

    def test_fires_when_probes_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_probes_empty_list(self) -> None:
        resource = {"properties": {"probes": []}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_probe_configured(self) -> None:
        resource = {
            "properties": {
                "probes": [
                    {
                        "name": "HealthProbe",
                        "properties": {
                            "protocol": "Http",
                            "path": "/health",
                            "interval": 30,
                            "timeout": 30,
                            "unhealthyThreshold": 3,
                        },
                    }
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_AGW_002["rule_id"] == "REL-AGW-002"
        assert REL_AGW_002["pillar"] == "reliability"
        assert "microsoft.network/applicationgateways" in REL_AGW_002["resource_types"]


@pytest.mark.unit
class TestRelSb001:
    """REL-SB-001 — Service Bus Basic tier."""

    _dsl = REL_SB_001["condition_dsl"]

    def test_fires_when_basic_tier(self) -> None:
        resource = {"sku": {"name": "Basic", "tier": "Basic"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard(self) -> None:
        resource = {"sku": {"name": "Standard", "tier": "Standard"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_premium(self) -> None:
        resource = {"sku": {"name": "Premium", "tier": "Premium"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_SB_001["rule_id"] == "REL-SB-001"
        assert "microsoft.servicebus/namespaces" in REL_SB_001["resource_types"]


@pytest.mark.unit
class TestRelAsr001:
    """REL-ASR-001 — Recovery Services vault missing cross-region restore."""

    _dsl = REL_ASR_001["condition_dsl"]

    def test_fires_when_redundancy_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_crr_disabled(self) -> None:
        resource = {
            "properties": {
                "redundancySettings": {"crossRegionRestore": "Disabled"}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_crr_not_set(self) -> None:
        resource = {
            "properties": {
                "redundancySettings": {"storageModelType": "GeoRedundant"}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_crr_enabled(self) -> None:
        resource = {
            "properties": {
                "redundancySettings": {
                    "storageModelType": "GeoRedundant",
                    "crossRegionRestore": "Enabled",
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_ASR_001["rule_id"] == "REL-ASR-001"
        assert "microsoft.recoveryservices/vaults" in REL_ASR_001["resource_types"]


# ===========================================================================
# Operational Excellence Rules
# ===========================================================================

@pytest.mark.unit
class TestOpsDiag001:
    """OPS-DIAG-001 — VM boot diagnostics disabled."""

    _dsl = OPS_DIAG_001["condition_dsl"]

    def test_fires_when_diagnostics_profile_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_boot_diagnostics_null(self) -> None:
        resource = {"properties": {"diagnosticsProfile": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_boot_diagnostics_disabled(self) -> None:
        resource = {
            "properties": {
                "diagnosticsProfile": {
                    "bootDiagnostics": {"enabled": False}
                }
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_boot_diagnostics_enabled(self) -> None:
        resource = {
            "properties": {
                "diagnosticsProfile": {
                    "bootDiagnostics": {
                        "enabled": True,
                        "storageUri": "https://sa.blob.core.windows.net",
                    }
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_DIAG_001["rule_id"] == "OPS-DIAG-001"
        assert OPS_DIAG_001["pillar"] == "operational_excellence"


@pytest.mark.unit
class TestOpsSlot001:
    """OPS-SLOT-001 — App Service plan tier does not support deployment slots."""

    _dsl = OPS_SLOT_001["condition_dsl"]

    def test_fires_on_free_tier(self) -> None:
        resource = {"sku": {"tier": "Free", "name": "F1"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_on_shared_tier(self) -> None:
        resource = {"sku": {"tier": "Shared", "name": "D1"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_on_basic_tier(self) -> None:
        resource = {"sku": {"tier": "Basic", "name": "B1"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_on_dynamic_consumption_plan(self) -> None:
        resource = {"sku": {"tier": "Dynamic", "name": "Y1"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_on_standard_tier(self) -> None:
        resource = {"sku": {"tier": "Standard", "name": "S1"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_on_premium_tier(self) -> None:
        resource = {"sku": {"tier": "PremiumV3", "name": "P1v3"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_SLOT_001["rule_id"] == "OPS-SLOT-001"
        assert "microsoft.web/serverfarms" in OPS_SLOT_001["resource_types"]


@pytest.mark.unit
class TestOpsMon001:
    """OPS-MON-001 — App Service missing Application Insights."""

    _dsl = OPS_MON_001["condition_dsl"]

    def test_fires_when_app_settings_null(self) -> None:
        resource = {"properties": {"siteConfig": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_site_config_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_ai_connection_string_absent(self) -> None:
        resource = {
            "properties": {
                "siteConfig": {
                    "appSettings": [
                        {"name": "WEBSITE_NODE_DEFAULT_VERSION", "value": "~18"},
                        {"name": "FUNCTIONS_EXTENSION_VERSION", "value": "~4"},
                    ]
                }
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_connection_string_present(self) -> None:
        resource = {
            "properties": {
                "siteConfig": {
                    "appSettings": [
                        {
                            "name": "APPLICATIONINSIGHTS_CONNECTION_STRING",
                            "value": "InstrumentationKey=abc123;IngestionEndpoint=...",
                        }
                    ]
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_legacy_key_present(self) -> None:
        resource = {
            "properties": {
                "siteConfig": {
                    "appSettings": [
                        {"name": "APPINSIGHTS_INSTRUMENTATIONKEY", "value": "abc-123-def"}
                    ]
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_MON_001["rule_id"] == "OPS-MON-001"
        assert "microsoft.web/sites" in OPS_MON_001["resource_types"]


# ===========================================================================
# Performance Efficiency Rules
# ===========================================================================

@pytest.mark.unit
class TestPerAlert001:
    """PER-ALERT-001 — Metric alert rule has no action group."""

    _dsl = PER_ALERT_001["condition_dsl"]

    def test_fires_when_actions_null(self) -> None:
        resource = {"properties": {"severity": 2, "enabled": True}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_actions_empty(self) -> None:
        resource = {"properties": {"severity": 1, "actions": []}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_action_group_present(self) -> None:
        resource = {
            "properties": {
                "severity": 1,
                "actions": [
                    {
                        "actionGroupId": (
                            "/subscriptions/x/resourceGroups/y/"
                            "providers/microsoft.insights/actionGroups/OpsAlerts"
                        )
                    }
                ],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_ALERT_001["rule_id"] == "PER-ALERT-001"
        assert PER_ALERT_001["pillar"] == "performance_efficiency"
        assert "microsoft.insights/metricalerts" in PER_ALERT_001["resource_types"]


# ===========================================================================
# Cost Optimization Rules
# ===========================================================================

@pytest.mark.unit
class TestCstBudget001:
    """CST-BUDGET-001 — Azure Budget has no alert notification thresholds."""

    _dsl = CST_BUDGET_001["condition_dsl"]

    def test_fires_when_notifications_null(self) -> None:
        resource = {"properties": {"amount": 1000, "timeGrain": "Monthly"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_notifications_empty(self) -> None:
        resource = {
            "properties": {
                "amount": 1000,
                "timeGrain": "Monthly",
                "notifications": [],
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_threshold_configured(self) -> None:
        resource = {
            "properties": {
                "amount": 5000,
                "timeGrain": "Monthly",
                "notifications": [
                    {
                        "enabled": True,
                        "operator": "GreaterThan",
                        "threshold": 80,
                        "contactEmails": ["finance@example.com"],
                        "contactRoles": [],
                        "thresholdType": "Actual",
                    }
                ],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_BUDGET_001["rule_id"] == "CST-BUDGET-001"
        assert CST_BUDGET_001["pillar"] == "cost_optimization"
        assert "microsoft.consumption/budgets" in CST_BUDGET_001["resource_types"]


@pytest.mark.unit
class TestCstCostTag001:
    """CST-COST-TAG-001 — Missing cost allocation tags."""

    _dsl = CST_COST_TAG_001["condition_dsl"]

    def test_fires_when_no_tags_at_all(self) -> None:
        resource = {"name": "my-vm", "type": "Microsoft.Compute/virtualMachines"}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tags_empty(self) -> None:
        resource = {"tags": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tags_have_no_cost_fields(self) -> None:
        resource = {"tags": {"Environment": "Production", "Owner": "platform-team"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_costcenter_tag_present_title_case(self) -> None:
        resource = {"tags": {"CostCenter": "CC-1042", "Environment": "Production"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_costcenter_lowercase(self) -> None:
        resource = {"tags": {"costcenter": "1042"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_team_tag_present(self) -> None:
        resource = {"tags": {"Team": "platform", "Environment": "prod"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_department_tag_present(self) -> None:
        resource = {"tags": {"Department": "Engineering"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_COST_TAG_001["rule_id"] == "CST-COST-TAG-001"
        assert "*" in CST_COST_TAG_001["resource_types"]


# ===========================================================================
# Reliability Rules — Phase 4 expansion
# ===========================================================================

@pytest.mark.unit
class TestRelStor004:
    """REL-STOR-004 — Blob versioning not enabled."""

    _dsl = REL_STOR_004["condition_dsl"]

    def test_fires_when_blob_service_properties_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_versioning_false(self) -> None:
        resource = {
            "properties": {
                "blobServiceProperties": {"isVersioningEnabled": False}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_versioning_absent(self) -> None:
        resource = {
            "properties": {
                "blobServiceProperties": {"deleteRetentionPolicy": {"enabled": True}}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_versioning_enabled(self) -> None:
        resource = {
            "properties": {
                "blobServiceProperties": {"isVersioningEnabled": True}
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_STOR_004["rule_id"] == "REL-STOR-004"
        assert REL_STOR_004["pillar"] == "reliability"
        assert "microsoft.storage/storageaccounts" in REL_STOR_004["resource_types"]
        assert REL_STOR_004["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestRelLb002:
    """REL-LB-002 — Load balancer has no health probes configured."""

    _dsl = REL_LB_002["condition_dsl"]

    def test_fires_when_probes_null(self) -> None:
        resource = {"properties": {"frontendIPConfigurations": []}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_probes_empty_list(self) -> None:
        resource = {"properties": {"probes": []}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_probe_configured(self) -> None:
        resource = {
            "properties": {
                "probes": [
                    {
                        "name": "HealthProbe",
                        "properties": {
                            "protocol": "Http",
                            "port": 80,
                            "requestPath": "/health",
                            "intervalInSeconds": 15,
                            "numberOfProbes": 2,
                        },
                    }
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_LB_002["rule_id"] == "REL-LB-002"
        assert REL_LB_002["pillar"] == "reliability"
        assert "microsoft.network/loadbalancers" in REL_LB_002["resource_types"]
        assert REL_LB_002["severity"] == "high"


@pytest.mark.unit
class TestRelCosmos001:
    """REL-COSMOS-001 — Cosmos DB single region."""

    _dsl = REL_COSMOS_001["condition_dsl"]

    def test_fires_when_locations_null(self) -> None:
        resource = {"properties": {"databaseAccountOfferType": "Standard"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_single_region(self) -> None:
        resource = {
            "properties": {
                "locations": [
                    {"locationName": "East US", "failoverPriority": 0}
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_locations_empty(self) -> None:
        resource = {"properties": {"locations": []}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_multi_region(self) -> None:
        resource = {
            "properties": {
                "locations": [
                    {"locationName": "East US", "failoverPriority": 0},
                    {"locationName": "West US", "failoverPriority": 1},
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_COSMOS_001["rule_id"] == "REL-COSMOS-001"
        assert REL_COSMOS_001["pillar"] == "reliability"
        assert "microsoft.documentdb/databaseaccounts" in REL_COSMOS_001["resource_types"]
        assert REL_COSMOS_001["severity"] == "high"


@pytest.mark.unit
class TestRelAks001:
    """REL-AKS-001 — AKS cluster not zone-redundant."""

    _dsl = REL_AKS_001["condition_dsl"]

    def test_fires_when_agent_pool_profiles_null(self) -> None:
        resource = {"properties": {"kubernetesVersion": "1.28.0"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_pool_has_no_zones(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 3}
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_pool_has_single_zone(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 3, "availabilityZones": ["1"]}
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_any_pool_lacks_zones(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 3, "availabilityZones": ["1", "2", "3"]},
                    {"name": "user", "count": 2},
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_all_pools_zone_redundant(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 3, "availabilityZones": ["1", "2", "3"]},
                    {"name": "user", "count": 3, "availabilityZones": ["1", "2", "3"]},
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_two_zones(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 2, "availabilityZones": ["1", "2"]},
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_AKS_001["rule_id"] == "REL-AKS-001"
        assert REL_AKS_001["pillar"] == "reliability"
        assert "microsoft.containerservice/managedclusters" in REL_AKS_001["resource_types"]
        assert REL_AKS_001["severity"] == "high"


@pytest.mark.unit
class TestRelApp004:
    """REL-APP-004 — App Service plan zone redundancy not enabled."""

    _dsl = REL_APP_004["condition_dsl"]

    def test_fires_when_zone_redundant_absent(self) -> None:
        resource = {"properties": {"sku": "P1v3"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_zone_redundant_false(self) -> None:
        resource = {"properties": {"zoneRedundant": False}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_zone_redundant_true(self) -> None:
        resource = {"properties": {"zoneRedundant": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_APP_004["rule_id"] == "REL-APP-004"
        assert REL_APP_004["pillar"] == "reliability"
        assert "microsoft.web/serverfarms" in REL_APP_004["resource_types"]
        assert REL_APP_004["severity"] == "medium"


@pytest.mark.unit
class TestRelEh001:
    """REL-EH-001 — Event Hub namespace on Basic tier."""

    _dsl = REL_EH_001["condition_dsl"]

    def test_fires_when_basic_tier(self) -> None:
        resource = {"sku": {"name": "Basic", "tier": "Basic"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard(self) -> None:
        resource = {"sku": {"name": "Standard", "tier": "Standard"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_premium(self) -> None:
        resource = {"sku": {"name": "Premium", "tier": "Premium"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_EH_001["rule_id"] == "REL-EH-001"
        assert REL_EH_001["pillar"] == "reliability"
        assert "microsoft.eventhub/namespaces" in REL_EH_001["resource_types"]
        assert REL_EH_001["severity"] == "medium"


@pytest.mark.unit
class TestRelMysql001:
    """REL-MYSQL-001 — MySQL Flexible Server HA not zone-redundant."""

    _dsl = REL_MYSQL_001["condition_dsl"]

    def test_fires_when_high_availability_null(self) -> None:
        resource = {"properties": {"version": "8.0"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_ha_disabled(self) -> None:
        resource = {"properties": {"highAvailability": {"mode": "Disabled"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_ha_same_zone(self) -> None:
        resource = {"properties": {"highAvailability": {"mode": "SameZone"}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_ha_zone_redundant(self) -> None:
        resource = {
            "properties": {
                "highAvailability": {
                    "mode": "ZoneRedundant",
                    "standbyAvailabilityZone": "2",
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_MYSQL_001["rule_id"] == "REL-MYSQL-001"
        assert REL_MYSQL_001["pillar"] == "reliability"
        assert "microsoft.dbformysql/flexibleservers" in REL_MYSQL_001["resource_types"]
        assert REL_MYSQL_001["severity"] == "high"


@pytest.mark.unit
class TestRelPostgres001:
    """REL-POSTGRES-001 — PostgreSQL Flexible Server HA not zone-redundant."""

    _dsl = REL_POSTGRES_001["condition_dsl"]

    def test_fires_when_high_availability_null(self) -> None:
        resource = {"properties": {"version": "15"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_ha_disabled(self) -> None:
        resource = {"properties": {"highAvailability": {"mode": "Disabled"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_ha_same_zone(self) -> None:
        resource = {"properties": {"highAvailability": {"mode": "SameZone"}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_ha_zone_redundant(self) -> None:
        resource = {
            "properties": {
                "highAvailability": {
                    "mode": "ZoneRedundant",
                    "standbyAvailabilityZone": "3",
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_POSTGRES_001["rule_id"] == "REL-POSTGRES-001"
        assert REL_POSTGRES_001["pillar"] == "reliability"
        assert "microsoft.dbforpostgresql/flexibleservers" in REL_POSTGRES_001["resource_types"]
        assert REL_POSTGRES_001["severity"] == "high"


@pytest.mark.unit
class TestRelRedis001:
    """REL-REDIS-001 — Azure Cache for Redis Premium not zone-redundant."""

    _dsl = REL_REDIS_001["condition_dsl"]

    def test_fires_when_premium_and_no_zones(self) -> None:
        resource = {"sku": {"name": "Premium", "family": "P", "capacity": 1}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premium_and_zones_empty(self) -> None:
        resource = {
            "sku": {"name": "Premium", "family": "P", "capacity": 1},
            "zones": [],
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premium_and_single_zone(self) -> None:
        resource = {
            "sku": {"name": "Premium", "family": "P", "capacity": 1},
            "zones": ["1"],
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_premium_and_multi_zone(self) -> None:
        resource = {
            "sku": {"name": "Premium", "family": "P", "capacity": 1},
            "zones": ["1", "2", "3"],
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_no_zones(self) -> None:
        """Standard SKU does not support zones — rule is Not Applicable."""
        resource = {"sku": {"name": "Standard", "family": "C", "capacity": 1}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_basic_no_zones(self) -> None:
        """Basic SKU does not support zones — rule is Not Applicable."""
        resource = {"sku": {"name": "Basic", "family": "C", "capacity": 0}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_REDIS_001["rule_id"] == "REL-REDIS-001"
        assert REL_REDIS_001["pillar"] == "reliability"
        assert "microsoft.cache/redis" in REL_REDIS_001["resource_types"]
        assert REL_REDIS_001["severity"] == "medium"


@pytest.mark.unit
class TestRelAgw003:
    """REL-AGW-003 — Application Gateway not zone-redundant."""

    _dsl = REL_AGW_003["condition_dsl"]

    def test_fires_when_zones_null(self) -> None:
        resource = {"properties": {"sku": {"name": "WAF_v2"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_zones_empty_list(self) -> None:
        resource = {
            "properties": {"sku": {"name": "WAF_v2"}},
            "zones": [],
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_zone_redundant(self) -> None:
        resource = {
            "properties": {"sku": {"name": "WAF_v2", "capacity": 2}},
            "zones": ["1", "2", "3"],
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_two_zones(self) -> None:
        resource = {
            "properties": {"sku": {"name": "Standard_v2"}},
            "zones": ["1", "2"],
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_AGW_003["rule_id"] == "REL-AGW-003"
        assert REL_AGW_003["pillar"] == "reliability"
        assert "microsoft.network/applicationgateways" in REL_AGW_003["resource_types"]
        assert REL_AGW_003["severity"] == "high"


# ===========================================================================
# Advisor-mapped rules: structural validation only (no DSL to evaluate)
# ===========================================================================

@pytest.mark.unit
class TestAdvisorMappedRules:
    """Validate that advisor_mapped rules have correct metadata and no condition_dsl."""

    def test_per_adv_001_metadata(self) -> None:
        from waf_catalog.rule_definitions import PER_ADV_001
        assert PER_ADV_001["rule_id"] == "PER-ADV-001"
        assert PER_ADV_001["evaluation_type"] == "advisor_mapped"
        assert PER_ADV_001["condition_dsl"] is None
        assert PER_ADV_001["prompt_template_ref"] == "advisor-performance-general"
        assert "*" in PER_ADV_001["resource_types"]

    def test_per_lt_001_metadata(self) -> None:
        from waf_catalog.rule_definitions import PER_LT_001
        assert PER_LT_001["rule_id"] == "PER-LT-001"
        assert PER_LT_001["evaluation_type"] == "advisor_mapped"
        assert PER_LT_001["condition_dsl"] is None
        assert "*" in PER_LT_001["resource_types"]

    def test_cst_adv_001_metadata(self) -> None:
        from waf_catalog.rule_definitions import CST_ADV_001
        assert CST_ADV_001["rule_id"] == "CST-ADV-001"
        assert CST_ADV_001["evaluation_type"] == "advisor_mapped"
        assert CST_ADV_001["condition_dsl"] is None
        assert CST_ADV_001["prompt_template_ref"] == "advisor-cost-general"


# ===========================================================================
# Catalogue integrity
# ===========================================================================

@pytest.mark.unit
class TestCatalogueIntegrity:
    """Cross-cutting checks across all NEW_RULES entries."""

    def test_all_rules_have_required_fields(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        required = {
            "rule_id", "pillar", "resource_types", "evaluation_type",
            "severity", "title", "description", "recommendation", "is_active",
        }
        for rule in NEW_RULES:
            missing = required - set(rule.keys())
            assert not missing, f"Rule {rule.get('rule_id')} is missing fields: {missing}"

    def test_deterministic_rules_have_condition_dsl(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        for rule in NEW_RULES:
            if rule["evaluation_type"] == "deterministic":
                assert rule.get("condition_dsl") is not None, (
                    f"Deterministic rule {rule['rule_id']} has no condition_dsl"
                )

    def test_advisor_rules_have_no_condition_dsl(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        for rule in NEW_RULES:
            if rule["evaluation_type"] == "advisor_mapped":
                assert rule.get("condition_dsl") is None, (
                    f"Advisor-mapped rule {rule['rule_id']} should not have condition_dsl"
                )
                assert rule.get("prompt_template_ref") is not None, (
                    f"Advisor-mapped rule {rule['rule_id']} should have prompt_template_ref"
                )

    def test_rule_ids_are_unique(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        ids = [r["rule_id"] for r in NEW_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule_id detected in NEW_RULES"

    def test_eighty_seven_new_rules_defined(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        assert len(NEW_RULES) == 87, (
            f"Expected 87 new rules, got {len(NEW_RULES)}"
        )

    def test_all_pillars_have_valid_values(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        valid_pillars = {
            "security", "reliability", "cost_optimization",
            "operational_excellence", "performance_efficiency",
        }
        for rule in NEW_RULES:
            assert rule["pillar"] in valid_pillars, (
                f"Rule {rule['rule_id']} has invalid pillar '{rule['pillar']}'"
            )

    def test_severity_values_are_valid(self) -> None:
        from waf_catalog.rule_definitions import NEW_RULES
        valid = {"critical", "high", "medium", "low", "informational"}
        for rule in NEW_RULES:
            assert rule["severity"] in valid, (
                f"Rule {rule['rule_id']} has invalid severity '{rule['severity']}'"
            )

    def test_human_review_controls_documented(self) -> None:
        from waf_catalog.rule_definitions import HUMAN_REVIEW_REQUIRED
        assert "SE-10" in HUMAN_REVIEW_REQUIRED
        assert "OE-03" in HUMAN_REVIEW_REQUIRED
        assert "OE-04" in HUMAN_REVIEW_REQUIRED
        assert "CO-09" in HUMAN_REVIEW_REQUIRED

    def test_mapping_coverage_expected_controls(self) -> None:
        """Verify expected WAF codes appear in NEWLY_COVERED_CONTROLS."""
        from waf_catalog.rule_definitions import NEWLY_COVERED_CONTROLS
        expected = {
            # Phase 3
            "SE-02", "SE-06", "SE-09",
            "RE-04", "RE-06", "RE-09",
            "OE-02", "OE-08", "OE-09", "OE-10", "OE-11",
            "PE-01", "PE-03", "PE-04", "PE-09", "PE-12",
            "CO-01", "CO-02", "CO-04", "CO-08", "CO-12",
            # Phase 4 — Reliability expansion
            "RE-02", "RE-03", "RE-05", "RE-08",
            # Phase 5 — Cost Optimization expansion
            "CO-05", "CO-06", "CO-07", "CO-10",
            # Phase 6 — Operational Excellence expansion
            "OE-12",
        }
        missing = expected - set(NEWLY_COVERED_CONTROLS)
        assert not missing, f"Expected controls not in NEWLY_COVERED_CONTROLS: {missing}"


# ===========================================================================
# Cost Optimization Rules — Phase 5 expansion
# ===========================================================================

@pytest.mark.unit
class TestCstStor003:
    """CST-STOR-003 — StorageV2 account missing last-access-time tracking."""

    _dsl = CST_STOR_003["condition_dsl"]

    def test_fires_when_storagev2_and_tracking_null(self) -> None:
        resource = {"kind": "StorageV2", "properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_storagev2_and_tracking_disabled(self) -> None:
        resource = {
            "kind": "StorageV2",
            "properties": {
                "blobServiceProperties": {
                    "lastAccessTimeTrackingPolicy": {"enable": False}
                }
            },
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_storagev2_and_tracking_policy_absent(self) -> None:
        resource = {
            "kind": "StorageV2",
            "properties": {"blobServiceProperties": {}},
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_storagev2_and_tracking_enabled(self) -> None:
        resource = {
            "kind": "StorageV2",
            "properties": {
                "blobServiceProperties": {
                    "lastAccessTimeTrackingPolicy": {"enable": True}
                }
            },
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_not_storagev2(self) -> None:
        """FileStorage accounts are Not Applicable — rule scoped to StorageV2 only."""
        resource = {
            "kind": "FileStorage",
            "properties": {},
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_STOR_003["rule_id"] == "CST-STOR-003"
        assert CST_STOR_003["pillar"] == "cost_optimization"
        assert "microsoft.storage/storageaccounts" in CST_STOR_003["resource_types"]
        assert CST_STOR_003["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestCstApp001:
    """CST-APP-001 — Premium App Service plan with single instance."""

    _dsl = CST_APP_001["condition_dsl"]

    def test_fires_when_premiumv2_single_instance(self) -> None:
        resource = {"sku": {"tier": "PremiumV2", "capacity": 1}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premiumv3_single_instance(self) -> None:
        resource = {"sku": {"tier": "PremiumV3", "capacity": 1}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_isolated_single_instance(self) -> None:
        resource = {"sku": {"tier": "Isolated", "capacity": 1}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_premiumv3_three_instances(self) -> None:
        resource = {"sku": {"tier": "PremiumV3", "capacity": 3}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_single_instance(self) -> None:
        """Standard tier single-instance is not flagged — rule targets Premium over-spend."""
        resource = {"sku": {"tier": "Standard", "capacity": 1}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_APP_001["rule_id"] == "CST-APP-001"
        assert CST_APP_001["pillar"] == "cost_optimization"
        assert "microsoft.web/serverfarms" in CST_APP_001["resource_types"]
        assert CST_APP_001["severity"] == "medium"


@pytest.mark.unit
class TestCstSnap001:
    """CST-SNAP-001 — Managed disk snapshot is non-incremental (full)."""

    _dsl = CST_SNAP_001["condition_dsl"]

    def test_fires_when_incremental_false(self) -> None:
        resource = {"properties": {"incremental": False, "diskSizeGB": 128}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_incremental_absent(self) -> None:
        resource = {"properties": {"diskSizeGB": 128}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_incremental_true(self) -> None:
        resource = {"properties": {"incremental": True, "diskSizeGB": 128}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_SNAP_001["rule_id"] == "CST-SNAP-001"
        assert CST_SNAP_001["pillar"] == "cost_optimization"
        assert "microsoft.compute/snapshots" in CST_SNAP_001["resource_types"]
        assert CST_SNAP_001["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestCstNic001:
    """CST-NIC-001 — Orphaned network interface not attached to any VM."""

    _dsl = CST_NIC_001["condition_dsl"]

    def test_fires_when_virtual_machine_null(self) -> None:
        resource = {"properties": {"ipConfigurations": []}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_properties_has_no_vm_key(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_vm_attached(self) -> None:
        resource = {
            "properties": {
                "virtualMachine": {
                    "id": (
                        "/subscriptions/xxx/resourceGroups/rg"
                        "/providers/Microsoft.Compute/virtualMachines/vm1"
                    )
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_NIC_001["rule_id"] == "CST-NIC-001"
        assert CST_NIC_001["pillar"] == "cost_optimization"
        assert "microsoft.network/networkinterfaces" in CST_NIC_001["resource_types"]
        assert CST_NIC_001["severity"] == "low"


@pytest.mark.unit
class TestCstLog001:
    """CST-LOG-001 — Log Analytics workspace retention > 90 days."""

    _dsl = CST_LOG_001["condition_dsl"]

    def test_fires_when_retention_180_days(self) -> None:
        resource = {"properties": {"retentionInDays": 180}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_retention_91_days(self) -> None:
        resource = {"properties": {"retentionInDays": 91}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_retention_730_days(self) -> None:
        resource = {"properties": {"retentionInDays": 730}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_retention_90_days(self) -> None:
        resource = {"properties": {"retentionInDays": 90}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_retention_30_days(self) -> None:
        resource = {"properties": {"retentionInDays": 30}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_LOG_001["rule_id"] == "CST-LOG-001"
        assert CST_LOG_001["pillar"] == "cost_optimization"
        assert "microsoft.operationalinsights/workspaces" in CST_LOG_001["resource_types"]
        assert CST_LOG_001["severity"] == "medium"


@pytest.mark.unit
class TestCstScale001:
    """CST-SCALE-001 — App Service plan Standard+ with autoscale disabled."""

    _dsl = CST_SCALE_001["condition_dsl"]

    def test_fires_when_standard_and_autoscale_absent(self) -> None:
        resource = {"sku": {"tier": "Standard"}, "properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premiumv3_and_autoscale_false(self) -> None:
        resource = {
            "sku": {"tier": "PremiumV3"},
            "properties": {"autoScaleEnabled": False},
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard_and_autoscale_enabled(self) -> None:
        resource = {
            "sku": {"tier": "Standard"},
            "properties": {"autoScaleEnabled": True},
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_basic_tier(self) -> None:
        """Basic tier does not support autoscale — Not Applicable."""
        resource = {"sku": {"tier": "Basic"}, "properties": {}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_free_tier(self) -> None:
        """Free tier does not support autoscale — Not Applicable."""
        resource = {"sku": {"tier": "Free"}, "properties": {}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_SCALE_001["rule_id"] == "CST-SCALE-001"
        assert CST_SCALE_001["pillar"] == "cost_optimization"
        assert "microsoft.web/serverfarms" in CST_SCALE_001["resource_types"]
        assert CST_SCALE_001["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestCstPrem001:
    """CST-PREM-001 — StorageV2 account on Premium tier."""

    _dsl = CST_PREM_001["condition_dsl"]

    def test_fires_when_storagev2_and_premium(self) -> None:
        resource = {"kind": "StorageV2", "sku": {"tier": "Premium", "name": "Premium_LRS"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_storagev2_and_standard(self) -> None:
        resource = {"kind": "StorageV2", "sku": {"tier": "Standard", "name": "Standard_LRS"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_filestorage_and_premium(self) -> None:
        """Premium FileStorage is a valid pattern — Not Applicable."""
        resource = {"kind": "FileStorage", "sku": {"tier": "Premium", "name": "Premium_LRS"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_blockblobstorage_and_premium(self) -> None:
        """Premium BlockBlobStorage is a valid pattern — Not Applicable."""
        resource = {
            "kind": "BlockBlobStorage",
            "sku": {"tier": "Premium", "name": "Premium_LRS"},
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_PREM_001["rule_id"] == "CST-PREM-001"
        assert CST_PREM_001["pillar"] == "cost_optimization"
        assert "microsoft.storage/storageaccounts" in CST_PREM_001["resource_types"]
        assert CST_PREM_001["severity"] == "medium"


@pytest.mark.unit
class TestCstAks001:
    """CST-AKS-001 — AKS cluster node pools have autoscaler disabled."""

    _dsl = CST_AKS_001["condition_dsl"]

    def test_fires_when_agent_pool_profiles_null(self) -> None:
        resource = {"properties": {"kubernetesVersion": "1.29.0"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_pool_autoscaling_absent(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [{"name": "nodepool1", "count": 3}]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_pool_autoscaling_false(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "nodepool1", "count": 3, "enableAutoScaling": False}
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_any_pool_lacks_autoscaling(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 3, "enableAutoScaling": True,
                     "minCount": 1, "maxCount": 5},
                    {"name": "user", "count": 3, "enableAutoScaling": False},
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_all_pools_have_autoscaling(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "count": 3, "enableAutoScaling": True,
                     "minCount": 1, "maxCount": 5},
                    {"name": "user", "count": 3, "enableAutoScaling": True,
                     "minCount": 1, "maxCount": 10},
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_AKS_001["rule_id"] == "CST-AKS-001"
        assert CST_AKS_001["pillar"] == "cost_optimization"
        assert "microsoft.containerservice/managedclusters" in CST_AKS_001["resource_types"]
        assert CST_AKS_001["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestCstAgw002:
    """CST-AGW-002 — Application Gateway v1 SKU (deprecated)."""

    _dsl = CST_AGW_002["condition_dsl"]

    def test_fires_when_standard_v1_sku(self) -> None:
        resource = {"properties": {"sku": {"name": "Standard", "tier": "Standard", "capacity": 2}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_waf_v1_sku(self) -> None:
        resource = {"properties": {"sku": {"name": "WAF", "tier": "WAF", "capacity": 2}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard_v2_sku(self) -> None:
        resource = {
            "properties": {"sku": {"name": "Standard_v2", "tier": "Standard_v2"}},
            "zones": ["1", "2", "3"],
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_waf_v2_sku(self) -> None:
        resource = {
            "properties": {"sku": {"name": "WAF_v2", "tier": "WAF_v2"}},
            "zones": ["1", "2", "3"],
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_AGW_002["rule_id"] == "CST-AGW-002"
        assert CST_AGW_002["pillar"] == "cost_optimization"
        assert "microsoft.network/applicationgateways" in CST_AGW_002["resource_types"]
        assert CST_AGW_002["severity"] == "high"


@pytest.mark.unit
class TestCstGw001:
    """CST-GW-001 — VPN Gateway Basic SKU (deprecated)."""

    _dsl = CST_GW_001["condition_dsl"]

    def test_fires_when_vpn_gateway_basic(self) -> None:
        resource = {
            "sku": {"name": "Basic", "tier": "Basic"},
            "properties": {"gatewayType": "Vpn", "vpnType": "RouteBased"},
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_vpn_gateway_vpngw1(self) -> None:
        resource = {
            "sku": {"name": "VpnGw1", "tier": "VpnGw1"},
            "properties": {"gatewayType": "Vpn", "vpnType": "RouteBased"},
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_expressroute_basic(self) -> None:
        """Basic SKU on an ExpressRoute gateway — Not Applicable (rule targets VPN type only)."""
        resource = {
            "sku": {"name": "Basic", "tier": "Basic"},
            "properties": {"gatewayType": "ExpressRoute"},
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_GW_001["rule_id"] == "CST-GW-001"
        assert CST_GW_001["pillar"] == "cost_optimization"
        assert "microsoft.network/virtualnetworkgateways" in CST_GW_001["resource_types"]
        assert CST_GW_001["severity"] == "medium"


@pytest.mark.unit
class TestCstSql002:
    """CST-SQL-002 — SQL Database Premium/Business Critical not in elastic pool."""

    _dsl = CST_SQL_002["condition_dsl"]

    def test_fires_when_premium_and_no_elastic_pool(self) -> None:
        resource = {
            "sku": {"name": "P1", "tier": "Premium", "capacity": 125},
            "properties": {"elasticPoolId": None, "maxSizeBytes": 536870912000},
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_business_critical_and_no_elastic_pool(self) -> None:
        resource = {
            "sku": {"name": "BC_Gen5_4", "tier": "BusinessCritical"},
            "properties": {},
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_premium_in_elastic_pool(self) -> None:
        resource = {
            "sku": {"name": "P1", "tier": "Premium"},
            "properties": {
                "elasticPoolId": (
                    "/subscriptions/xxx/resourceGroups/rg"
                    "/providers/Microsoft.Sql/servers/sql1/elasticPools/pool1"
                )
            },
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_tier(self) -> None:
        """Standard tier — Not Applicable for this rule."""
        resource = {
            "sku": {"name": "S1", "tier": "Standard"},
            "properties": {"elasticPoolId": None},
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_SQL_002["rule_id"] == "CST-SQL-002"
        assert CST_SQL_002["pillar"] == "cost_optimization"
        assert "microsoft.sql/servers/databases" in CST_SQL_002["resource_types"]
        assert CST_SQL_002["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestCstCosmos001:
    """CST-COSMOS-001 — Cosmos DB multi-region writes enabled with single region."""

    _dsl = CST_COSMOS_001["condition_dsl"]

    def test_fires_when_multi_write_and_single_region(self) -> None:
        resource = {
            "properties": {
                "enableMultipleWriteLocations": True,
                "locations": [
                    {"locationName": "East US", "failoverPriority": 0}
                ],
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_multi_write_and_no_locations(self) -> None:
        resource = {
            "properties": {
                "enableMultipleWriteLocations": True,
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_multi_write_and_empty_locations(self) -> None:
        resource = {
            "properties": {
                "enableMultipleWriteLocations": True,
                "locations": [],
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_multi_write_and_multi_region(self) -> None:
        resource = {
            "properties": {
                "enableMultipleWriteLocations": True,
                "locations": [
                    {"locationName": "East US", "failoverPriority": 0},
                    {"locationName": "West US", "failoverPriority": 1},
                ],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_single_write_and_single_region(self) -> None:
        """Single-write-region with single region is a reliability concern, not a cost waste."""
        resource = {
            "properties": {
                "enableMultipleWriteLocations": False,
                "locations": [{"locationName": "East US", "failoverPriority": 0}],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_COSMOS_001["rule_id"] == "CST-COSMOS-001"
        assert CST_COSMOS_001["pillar"] == "cost_optimization"
        assert "microsoft.documentdb/databaseaccounts" in CST_COSMOS_001["resource_types"]
        assert CST_COSMOS_001["severity"] == "medium"


# ===========================================================================
# Operational Excellence Rules — Phase 6 expansion
# ===========================================================================

@pytest.mark.unit
class TestOpsAks001:
    """OPS-AKS-001 — AKS Container Insights (OMS agent) not enabled."""

    _dsl = OPS_AKS_001["condition_dsl"]

    def test_fires_when_omsagent_null(self) -> None:
        resource = {"properties": {"addonProfiles": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_omsagent_disabled(self) -> None:
        resource = {"properties": {"addonProfiles": {"omsAgent": {"enabled": False}}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_addonprofiles_absent(self) -> None:
        resource = {"properties": {"kubernetesVersion": "1.28.0"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_omsagent_enabled(self) -> None:
        resource = {
            "properties": {
                "addonProfiles": {
                    "omsAgent": {
                        "enabled": True,
                        "config": {"logAnalyticsWorkspaceResourceID": "/subscriptions/x/ws"},
                    }
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_AKS_001["rule_id"] == "OPS-AKS-001"
        assert OPS_AKS_001["pillar"] == "operational_excellence"
        assert "microsoft.containerservice/managedclusters" in OPS_AKS_001["resource_types"]
        assert OPS_AKS_001["severity"] == "medium"


@pytest.mark.unit
class TestOpsAks002:
    """OPS-AKS-002 — AKS cluster auto-upgrade channel not configured."""

    _dsl = OPS_AKS_002["condition_dsl"]

    def test_fires_when_upgrade_channel_null(self) -> None:
        resource = {"properties": {"autoUpgradeProfile": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_upgrade_channel_none(self) -> None:
        resource = {"properties": {"autoUpgradeProfile": {"upgradeChannel": "none"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_autoupgradeprofile_absent(self) -> None:
        resource = {"properties": {"kubernetesVersion": "1.27.0"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_channel_patch(self) -> None:
        resource = {"properties": {"autoUpgradeProfile": {"upgradeChannel": "patch"}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_channel_stable(self) -> None:
        resource = {"properties": {"autoUpgradeProfile": {"upgradeChannel": "stable"}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_AKS_002["rule_id"] == "OPS-AKS-002"
        assert OPS_AKS_002["pillar"] == "operational_excellence"
        assert OPS_AKS_002["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestOpsNsg001:
    """OPS-NSG-001 — NSG flow logs not configured."""

    _dsl = OPS_NSG_001["condition_dsl"]

    def test_fires_when_flowlogs_null(self) -> None:
        resource = {"properties": {"securityRules": []}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_flowlogs_empty(self) -> None:
        resource = {"properties": {"flowLogs": []}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_flowlogs_present(self) -> None:
        resource = {
            "properties": {
                "flowLogs": [
                    {"id": "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/networkWatchers/nw/flowLogs/fl1"}
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_NSG_001["rule_id"] == "OPS-NSG-001"
        assert OPS_NSG_001["pillar"] == "operational_excellence"
        assert "microsoft.network/networksecuritygroups" in OPS_NSG_001["resource_types"]


@pytest.mark.unit
class TestOpsCosmos001:
    """OPS-COSMOS-001 — Cosmos DB not using Continuous backup."""

    _dsl = OPS_COSMOS_001["condition_dsl"]

    def test_fires_when_backup_policy_null(self) -> None:
        resource = {"properties": {"enableMultipleWriteLocations": False}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_backup_policy_periodic(self) -> None:
        resource = {
            "properties": {
                "backupPolicy": {"type": "Periodic", "periodicModeProperties": {"backupIntervalInMinutes": 240}}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_backup_continuous(self) -> None:
        resource = {"properties": {"backupPolicy": {"type": "Continuous", "continuousModeProperties": {"tier": "Continuous30Days"}}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_COSMOS_001["rule_id"] == "OPS-COSMOS-001"
        assert OPS_COSMOS_001["pillar"] == "operational_excellence"
        assert "microsoft.documentdb/databaseaccounts" in OPS_COSMOS_001["resource_types"]
        assert OPS_COSMOS_001["severity"] == "medium"


@pytest.mark.unit
class TestOpsStor001:
    """OPS-STOR-001 — Storage account blob soft delete disabled."""

    _dsl = OPS_STOR_001["condition_dsl"]

    def test_fires_when_retention_policy_null(self) -> None:
        resource = {"properties": {"blobServiceProperties": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_soft_delete_disabled(self) -> None:
        resource = {
            "properties": {
                "blobServiceProperties": {
                    "deleteRetentionPolicy": {"enabled": False, "days": 7}
                }
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_blobserviceproperties_absent(self) -> None:
        resource = {"properties": {"supportsHttpsTrafficOnly": True}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_soft_delete_enabled(self) -> None:
        resource = {
            "properties": {
                "blobServiceProperties": {
                    "deleteRetentionPolicy": {"enabled": True, "days": 14}
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_STOR_001["rule_id"] == "OPS-STOR-001"
        assert OPS_STOR_001["pillar"] == "operational_excellence"
        assert "microsoft.storage/storageaccounts" in OPS_STOR_001["resource_types"]


@pytest.mark.unit
class TestOpsVmss001:
    """OPS-VMSS-001 — VMSS automatic OS upgrade not enabled."""

    _dsl = OPS_VMSS_001["condition_dsl"]

    def test_fires_when_autoupgrade_policy_null(self) -> None:
        resource = {"properties": {"upgradePolicy": {"mode": "Rolling"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_enable_automatic_upgrade_false(self) -> None:
        resource = {
            "properties": {
                "upgradePolicy": {
                    "automaticOSUpgradePolicy": {"enableAutomaticOSUpgrade": False}
                }
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_autoupgrade_enabled(self) -> None:
        resource = {
            "properties": {
                "upgradePolicy": {
                    "automaticOSUpgradePolicy": {"enableAutomaticOSUpgrade": True}
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_VMSS_001["rule_id"] == "OPS-VMSS-001"
        assert OPS_VMSS_001["pillar"] == "operational_excellence"
        assert "microsoft.compute/virtualmachinescalesets" in OPS_VMSS_001["resource_types"]


@pytest.mark.unit
class TestOpsRedis001:
    """OPS-REDIS-001 — Premium Redis RDB persistence not enabled."""

    _dsl = OPS_REDIS_001["condition_dsl"]

    def test_fires_when_premium_and_no_redis_config(self) -> None:
        resource = {"sku": {"name": "Premium", "capacity": 1}, "properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premium_and_rdb_disabled(self) -> None:
        resource = {
            "sku": {"name": "Premium"},
            "properties": {"redisConfiguration": {"rdb-backup-enabled": "false"}},
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premium_and_rdb_absent(self) -> None:
        resource = {
            "sku": {"name": "Premium"},
            "properties": {"redisConfiguration": {"maxmemory-policy": "allkeys-lru"}},
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_premium_and_rdb_enabled(self) -> None:
        resource = {
            "sku": {"name": "Premium"},
            "properties": {"redisConfiguration": {"rdb-backup-enabled": "true"}},
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_tier(self) -> None:
        """Standard tier does not support RDB persistence — Not Applicable."""
        resource = {"sku": {"name": "Standard"}, "properties": {}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_REDIS_001["rule_id"] == "OPS-REDIS-001"
        assert OPS_REDIS_001["pillar"] == "operational_excellence"
        assert "microsoft.cache/redis" in OPS_REDIS_001["resource_types"]


@pytest.mark.unit
class TestOpsApp003:
    """OPS-APP-003 — App Service health check path not configured."""

    _dsl = OPS_APP_003["condition_dsl"]

    def test_fires_when_healthcheckpath_null(self) -> None:
        resource = {"properties": {"siteConfig": {"alwaysOn": True}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_healthcheckpath_empty_string(self) -> None:
        resource = {"properties": {"siteConfig": {"healthCheckPath": ""}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_siteconfig_absent(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_healthcheck_configured(self) -> None:
        resource = {"properties": {"siteConfig": {"healthCheckPath": "/health"}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_custom_path_configured(self) -> None:
        resource = {"properties": {"siteConfig": {"healthCheckPath": "/api/status"}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_APP_003["rule_id"] == "OPS-APP-003"
        assert OPS_APP_003["pillar"] == "operational_excellence"
        assert "microsoft.web/sites" in OPS_APP_003["resource_types"]


@pytest.mark.unit
class TestOpsMysql001:
    """OPS-MYSQL-001 — MySQL Flexible Server backup retention < 14 days."""

    _dsl = OPS_MYSQL_001["condition_dsl"]

    def test_fires_when_backup_null(self) -> None:
        resource = {"properties": {"version": "8.0"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_retention_7_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 7}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_retention_13_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 13}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_retention_14_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 14}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_retention_35_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 35}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_MYSQL_001["rule_id"] == "OPS-MYSQL-001"
        assert OPS_MYSQL_001["pillar"] == "operational_excellence"
        assert "microsoft.dbformysql/flexibleservers" in OPS_MYSQL_001["resource_types"]


@pytest.mark.unit
class TestOpsPostgres001:
    """OPS-POSTGRES-001 — PostgreSQL Flexible Server backup retention < 14 days."""

    _dsl = OPS_POSTGRES_001["condition_dsl"]

    def test_fires_when_backup_null(self) -> None:
        resource = {"properties": {"version": "15"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_retention_7_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 7}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_retention_14_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 14}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_retention_30_days(self) -> None:
        resource = {"properties": {"backup": {"backupRetentionDays": 30}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_POSTGRES_001["rule_id"] == "OPS-POSTGRES-001"
        assert OPS_POSTGRES_001["pillar"] == "operational_excellence"
        assert "microsoft.dbforpostgresql/flexibleservers" in OPS_POSTGRES_001["resource_types"]


@pytest.mark.unit
class TestOpsAct001:
    """OPS-ACT-001 — Activity Log Alert has no action group."""

    _dsl = OPS_ACT_001["condition_dsl"]

    def test_fires_when_actions_null(self) -> None:
        resource = {"properties": {"enabled": True}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_action_groups_null(self) -> None:
        resource = {"properties": {"actions": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_action_groups_empty(self) -> None:
        resource = {"properties": {"actions": {"actionGroups": []}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_action_group_present(self) -> None:
        resource = {
            "properties": {
                "actions": {
                    "actionGroups": [
                        {"actionGroupId": "/subscriptions/xxx/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag1"}
                    ]
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_ACT_001["rule_id"] == "OPS-ACT-001"
        assert OPS_ACT_001["pillar"] == "operational_excellence"
        assert "microsoft.insights/activitylogalerts" in OPS_ACT_001["resource_types"]


@pytest.mark.unit
class TestOpsSql003:
    """OPS-SQL-003 — SQL Server auditing not enabled."""

    _dsl = OPS_SQL_003["condition_dsl"]

    def test_fires_when_auditing_settings_null(self) -> None:
        resource = {"properties": {"minimalTlsVersion": "1.2"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_auditing_state_disabled(self) -> None:
        resource = {"properties": {"auditingSettings": {"state": "Disabled"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_auditing_state_not_enabled(self) -> None:
        resource = {"properties": {"auditingSettings": {"state": "New"}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_auditing_enabled(self) -> None:
        resource = {
            "properties": {
                "auditingSettings": {
                    "state": "Enabled",
                    "isAzureMonitorTargetEnabled": True,
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_SQL_003["rule_id"] == "OPS-SQL-003"
        assert OPS_SQL_003["pillar"] == "operational_excellence"
        assert "microsoft.sql/servers" in OPS_SQL_003["resource_types"]
        assert OPS_SQL_003["evaluation_type"] == "deterministic"


# ===========================================================================
# Performance Efficiency Rules — Phase 7 expansion
# ===========================================================================

@pytest.mark.unit
class TestPerVm004:
    """PER-VM-004 — VM OS disk using Standard HDD (Standard_LRS)."""

    _dsl = PER_VM_004["condition_dsl"]

    def test_fires_when_os_disk_standard_lrs(self) -> None:
        resource = {
            "properties": {
                "storageProfile": {
                    "osDisk": {"managedDisk": {"storageAccountType": "Standard_LRS"}}
                }
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_os_disk_standard_ssd(self) -> None:
        resource = {
            "properties": {
                "storageProfile": {
                    "osDisk": {"managedDisk": {"storageAccountType": "StandardSSD_LRS"}}
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_os_disk_premium_ssd(self) -> None:
        resource = {
            "properties": {
                "storageProfile": {
                    "osDisk": {"managedDisk": {"storageAccountType": "Premium_LRS"}}
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_managed_disk_absent(self) -> None:
        """Unmanaged disk (legacy) — Not Applicable for this check."""
        resource = {"properties": {"storageProfile": {"osDisk": {"vhd": {"uri": "https://sa.blob.core.windows.net/vhds/disk.vhd"}}}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_VM_004["rule_id"] == "PER-VM-004"
        assert PER_VM_004["pillar"] == "performance_efficiency"
        assert "microsoft.compute/virtualmachines" in PER_VM_004["resource_types"]
        assert PER_VM_004["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestPerDisk001:
    """PER-DISK-001 — Managed disk is Standard HDD (Standard_LRS)."""

    _dsl = PER_DISK_001["condition_dsl"]

    def test_fires_when_standard_lrs(self) -> None:
        resource = {"sku": {"name": "Standard_LRS", "tier": "Standard"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard_ssd(self) -> None:
        resource = {"sku": {"name": "StandardSSD_LRS", "tier": "StandardSSD"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_premium_ssd(self) -> None:
        resource = {"sku": {"name": "Premium_LRS", "tier": "Premium"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_ultra_ssd(self) -> None:
        resource = {"sku": {"name": "UltraSSD_LRS", "tier": "Ultra"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_DISK_001["rule_id"] == "PER-DISK-001"
        assert PER_DISK_001["pillar"] == "performance_efficiency"
        assert "microsoft.compute/disks" in PER_DISK_001["resource_types"]


@pytest.mark.unit
class TestPerApp004:
    """PER-APP-004 — App Service plan on Free or Shared tier."""

    _dsl = PER_APP_004["condition_dsl"]

    def test_fires_when_free_tier(self) -> None:
        resource = {"sku": {"name": "F1", "tier": "Free"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_shared_tier(self) -> None:
        resource = {"sku": {"name": "D1", "tier": "Shared"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_basic_tier(self) -> None:
        resource = {"sku": {"name": "B1", "tier": "Basic"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_tier(self) -> None:
        resource = {"sku": {"name": "S1", "tier": "Standard"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_premium_tier(self) -> None:
        resource = {"sku": {"name": "P1v3", "tier": "PremiumV3"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_APP_004["rule_id"] == "PER-APP-004"
        assert PER_APP_004["pillar"] == "performance_efficiency"
        assert "microsoft.web/serverfarms" in PER_APP_004["resource_types"]


@pytest.mark.unit
class TestPerApp005:
    """PER-APP-005 — App Service AlwaysOn not enabled."""

    _dsl = PER_APP_005["condition_dsl"]

    def test_fires_when_alwayson_null(self) -> None:
        resource = {"properties": {"siteConfig": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_alwayson_false(self) -> None:
        resource = {"properties": {"siteConfig": {"alwaysOn": False}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_siteconfig_absent(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_alwayson_true(self) -> None:
        resource = {"properties": {"siteConfig": {"alwaysOn": True}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_APP_005["rule_id"] == "PER-APP-005"
        assert PER_APP_005["pillar"] == "performance_efficiency"
        assert "microsoft.web/sites" in PER_APP_005["resource_types"]


@pytest.mark.unit
class TestPerSql002:
    """PER-SQL-002 — SQL Database on Basic tier (5 DTU limit)."""

    _dsl = PER_SQL_002["condition_dsl"]

    def test_fires_when_basic_tier(self) -> None:
        resource = {"sku": {"name": "Basic", "tier": "Basic", "capacity": 5}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard_tier(self) -> None:
        resource = {"sku": {"name": "S1", "tier": "Standard", "capacity": 20}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_premium_tier(self) -> None:
        resource = {"sku": {"name": "P1", "tier": "Premium", "capacity": 125}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_general_purpose(self) -> None:
        resource = {"sku": {"name": "GP_Gen5_4", "tier": "GeneralPurpose"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_SQL_002["rule_id"] == "PER-SQL-002"
        assert PER_SQL_002["pillar"] == "performance_efficiency"
        assert "microsoft.sql/servers/databases" in PER_SQL_002["resource_types"]


@pytest.mark.unit
class TestPerRedis001:
    """PER-REDIS-001 — Premium Redis with no clustering (single shard)."""

    _dsl = PER_REDIS_001["condition_dsl"]

    def test_fires_when_premium_no_shards(self) -> None:
        resource = {"sku": {"name": "Premium", "capacity": 1}, "properties": {"shardCount": 0}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_premium_shardcount_null(self) -> None:
        resource = {"sku": {"name": "Premium", "capacity": 2}, "properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_premium_with_shards(self) -> None:
        resource = {"sku": {"name": "Premium", "capacity": 2}, "properties": {"shardCount": 3}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_tier(self) -> None:
        """Standard tier does not support clustering — Not Applicable."""
        resource = {"sku": {"name": "Standard", "capacity": 1}, "properties": {"shardCount": 0}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_basic_tier(self) -> None:
        resource = {"sku": {"name": "Basic", "capacity": 0}, "properties": {}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_REDIS_001["rule_id"] == "PER-REDIS-001"
        assert PER_REDIS_001["pillar"] == "performance_efficiency"
        assert "microsoft.cache/redis" in PER_REDIS_001["resource_types"]


@pytest.mark.unit
class TestPerLb001:
    """PER-LB-001 — Load Balancer Basic SKU — no performance SLA."""

    _dsl = PER_LB_001["condition_dsl"]

    def test_fires_when_basic_sku(self) -> None:
        resource = {"sku": {"name": "Basic"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_standard_sku(self) -> None:
        resource = {"sku": {"name": "Standard"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_gateway_sku(self) -> None:
        resource = {"sku": {"name": "Gateway"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_LB_001["rule_id"] == "PER-LB-001"
        assert PER_LB_001["pillar"] == "performance_efficiency"
        assert "microsoft.network/loadbalancers" in PER_LB_001["resource_types"]


@pytest.mark.unit
class TestPerAgw001:
    """PER-AGW-001 — Application Gateway v2 without autoscale configuration."""

    _dsl = PER_AGW_001["condition_dsl"]

    def test_fires_when_standard_v2_no_autoscale(self) -> None:
        resource = {
            "properties": {
                "sku": {"name": "Standard_v2", "tier": "Standard_v2", "capacity": 2},
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_waf_v2_autoscale_null(self) -> None:
        resource = {
            "properties": {
                "sku": {"name": "WAF_v2"},
                "autoscaleConfiguration": None,
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_waf_v2_mincapacity_null(self) -> None:
        resource = {
            "properties": {
                "sku": {"name": "WAF_v2"},
                "autoscaleConfiguration": {},
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_autoscale_configured(self) -> None:
        resource = {
            "properties": {
                "sku": {"name": "WAF_v2"},
                "autoscaleConfiguration": {"minCapacity": 2, "maxCapacity": 10},
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_v1_sku(self) -> None:
        """v1 SKUs — Not Applicable (rule targets v2 without autoscale)."""
        resource = {
            "properties": {
                "sku": {"name": "WAF", "tier": "WAF"},
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_AGW_001["rule_id"] == "PER-AGW-001"
        assert PER_AGW_001["pillar"] == "performance_efficiency"
        assert "microsoft.network/applicationgateways" in PER_AGW_001["resource_types"]


@pytest.mark.unit
class TestPerCdn002:
    """PER-CDN-002 — CDN endpoint has no custom caching delivery policy."""

    _dsl = PER_CDN_002["condition_dsl"]

    def test_fires_when_delivery_policy_null(self) -> None:
        resource = {"properties": {"originHostHeader": "contoso.azurewebsites.net"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_rules_null(self) -> None:
        resource = {"properties": {"deliveryPolicy": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_rules_empty(self) -> None:
        resource = {"properties": {"deliveryPolicy": {"rules": []}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_caching_rule_configured(self) -> None:
        resource = {
            "properties": {
                "deliveryPolicy": {
                    "rules": [
                        {
                            "name": "CacheImages",
                            "order": 1,
                            "conditions": [],
                            "actions": [{"name": "CacheExpiration"}],
                        }
                    ]
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_CDN_002["rule_id"] == "PER-CDN-002"
        assert PER_CDN_002["pillar"] == "performance_efficiency"
        assert "microsoft.cdn/profiles/endpoints" in PER_CDN_002["resource_types"]


@pytest.mark.unit
class TestPerSql003:
    """PER-SQL-003 — SQL Database Premium/BC read scale-out disabled."""

    _dsl = PER_SQL_003["condition_dsl"]

    def test_fires_when_premium_read_scale_disabled(self) -> None:
        resource = {
            "sku": {"name": "P1", "tier": "Premium"},
            "properties": {"readScale": "Disabled"},
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_business_critical_read_scale_absent(self) -> None:
        resource = {
            "sku": {"name": "BC_Gen5_4", "tier": "BusinessCritical"},
            "properties": {},
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_premium_read_scale_enabled(self) -> None:
        resource = {
            "sku": {"name": "P2", "tier": "Premium"},
            "properties": {"readScale": "Enabled"},
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_standard_tier(self) -> None:
        """Standard tier does not support read scale — Not Applicable."""
        resource = {
            "sku": {"name": "S1", "tier": "Standard"},
            "properties": {"readScale": "Disabled"},
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_SQL_003["rule_id"] == "PER-SQL-003"
        assert PER_SQL_003["pillar"] == "performance_efficiency"
        assert "microsoft.sql/servers/databases" in PER_SQL_003["resource_types"]


@pytest.mark.unit
class TestPerCosmos001:
    """PER-COSMOS-001 — Cosmos DB using Strong or BoundedStaleness consistency."""

    _dsl = PER_COSMOS_001["condition_dsl"]

    def test_fires_when_strong_consistency(self) -> None:
        resource = {
            "properties": {
                "consistencyPolicy": {"defaultConsistencyLevel": "Strong"}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_bounded_staleness(self) -> None:
        resource = {
            "properties": {
                "consistencyPolicy": {
                    "defaultConsistencyLevel": "BoundedStaleness",
                    "maxStalenessPrefix": 100000,
                }
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_session_consistency(self) -> None:
        resource = {
            "properties": {
                "consistencyPolicy": {"defaultConsistencyLevel": "Session"}
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_eventual_consistency(self) -> None:
        resource = {
            "properties": {
                "consistencyPolicy": {"defaultConsistencyLevel": "Eventual"}
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_consistent_prefix(self) -> None:
        resource = {
            "properties": {
                "consistencyPolicy": {"defaultConsistencyLevel": "ConsistentPrefix"}
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_COSMOS_001["rule_id"] == "PER-COSMOS-001"
        assert PER_COSMOS_001["pillar"] == "performance_efficiency"
        assert "microsoft.documentdb/databaseaccounts" in PER_COSMOS_001["resource_types"]


@pytest.mark.unit
class TestPerAks001:
    """PER-AKS-001 — AKS system node pool using B-series VM (burstable)."""

    _dsl = PER_AKS_001["condition_dsl"]

    def test_fires_when_system_pool_uses_b_series(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "mode": "System", "vmSize": "Standard_B2s", "count": 2},
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_fires_when_system_pool_uses_b4ms(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "mode": "System", "vmSize": "Standard_B4ms", "count": 3},
                    {"name": "user", "mode": "User", "vmSize": "Standard_D4s_v3", "count": 3},
                ]
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_system_pool_uses_dv3(self) -> None:
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "mode": "System", "vmSize": "Standard_D4s_v3", "count": 3},
                    {"name": "user", "mode": "User", "vmSize": "Standard_D8s_v3", "count": 5},
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_user_pool_uses_b_series(self) -> None:
        """B-series on user pool is acceptable (dev/test workloads)."""
        resource = {
            "properties": {
                "agentPoolProfiles": [
                    {"name": "system", "mode": "System", "vmSize": "Standard_D4s_v3", "count": 3},
                    {"name": "spot", "mode": "User", "vmSize": "Standard_B4ms", "count": 2},
                ]
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_agentpoolprofiles_absent(self) -> None:
        """No profiles — Not Applicable."""
        resource = {"properties": {"kubernetesVersion": "1.28.0"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert PER_AKS_001["rule_id"] == "PER-AKS-001"
        assert PER_AKS_001["pillar"] == "performance_efficiency"
        assert "microsoft.containerservice/managedclusters" in PER_AKS_001["resource_types"]


# ===========================================================================
# Phase 8 — Cross-pillar resource coverage expansion
# ===========================================================================

# ---------------------------------------------------------------------------
# Key Vault
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecKv006:
    """SEC-KV-006 — Key Vault RBAC authorization not enabled."""

    _dsl = SEC_KV_006["condition_dsl"]

    def test_fires_when_rbac_false(self) -> None:
        resource = {"properties": {"enableRbacAuthorization": False}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_rbac_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_rbac_enabled(self) -> None:
        resource = {"properties": {"enableRbacAuthorization": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_KV_006["rule_id"] == "SEC-KV-006"
        assert SEC_KV_006["pillar"] == "security"
        assert "microsoft.keyvault/vaults" in SEC_KV_006["resource_types"]
        assert SEC_KV_006["evaluation_type"] == "deterministic"


@pytest.mark.unit
class TestSecKv007:
    """SEC-KV-007 — Key Vault network access not restricted."""

    _dsl = SEC_KV_007["condition_dsl"]

    def test_fires_when_networkacls_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_default_action_allow(self) -> None:
        resource = {"properties": {"networkAcls": {"defaultAction": "Allow"}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_default_action_deny(self) -> None:
        resource = {"properties": {"networkAcls": {"defaultAction": "Deny", "ipRules": []}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_KV_007["rule_id"] == "SEC-KV-007"
        assert SEC_KV_007["pillar"] == "security"
        assert "microsoft.keyvault/vaults" in SEC_KV_007["resource_types"]


@pytest.mark.unit
class TestRelKv001:
    """REL-KV-001 — Key Vault purge protection not enabled."""

    _dsl = REL_KV_001["condition_dsl"]

    def test_fires_when_purge_protection_false(self) -> None:
        resource = {"properties": {"enablePurgeProtection": False}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_purge_protection_null(self) -> None:
        resource = {"properties": {"enableSoftDelete": True}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_purge_protection_enabled(self) -> None:
        resource = {"properties": {"enablePurgeProtection": True, "enableSoftDelete": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_KV_001["rule_id"] == "REL-KV-001"
        assert REL_KV_001["pillar"] == "reliability"
        assert "microsoft.keyvault/vaults" in REL_KV_001["resource_types"]


# ---------------------------------------------------------------------------
# Virtual Network
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRelVnet001:
    """REL-VNET-001 — VNet has no DDoS protection plan."""

    _dsl = REL_VNET_001["condition_dsl"]

    def test_fires_when_ddos_plan_null(self) -> None:
        resource = {"properties": {"addressSpace": {"addressPrefixes": ["10.0.0.0/16"]}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_ddos_plan_id_null(self) -> None:
        resource = {"properties": {"ddosProtectionPlan": {}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_ddos_plan_attached(self) -> None:
        resource = {
            "properties": {
                "ddosProtectionPlan": {
                    "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/ddosProtectionPlans/plan1"
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_VNET_001["rule_id"] == "REL-VNET-001"
        assert REL_VNET_001["pillar"] == "reliability"
        assert "microsoft.network/virtualnetworks" in REL_VNET_001["resource_types"]


@pytest.mark.unit
class TestOpsVnet001:
    """OPS-VNET-001 — VNet uses Azure-provided DNS (no custom DNS)."""

    _dsl = OPS_VNET_001["condition_dsl"]

    def test_fires_when_dhcp_options_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_dns_servers_null(self) -> None:
        resource = {"properties": {"dhcpOptions": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_dns_servers_empty(self) -> None:
        resource = {"properties": {"dhcpOptions": {"dnsServers": []}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_custom_dns_configured(self) -> None:
        resource = {"properties": {"dhcpOptions": {"dnsServers": ["10.0.0.4", "10.0.0.5"]}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_VNET_001["rule_id"] == "OPS-VNET-001"
        assert OPS_VNET_001["pillar"] == "operational_excellence"
        assert "microsoft.network/virtualnetworks" in OPS_VNET_001["resource_types"]


# ---------------------------------------------------------------------------
# Azure Firewall
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecAfw001:
    """SEC-AFW-001 — Azure Firewall threat intelligence mode is Off."""

    _dsl = SEC_AFW_001["condition_dsl"]

    def test_fires_when_threat_intel_off(self) -> None:
        resource = {"properties": {"threatIntelMode": "Off"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_threat_intel_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_threat_intel_alert(self) -> None:
        resource = {"properties": {"threatIntelMode": "Alert"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_threat_intel_deny(self) -> None:
        resource = {"properties": {"threatIntelMode": "Deny"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_AFW_001["rule_id"] == "SEC-AFW-001"
        assert SEC_AFW_001["pillar"] == "security"
        assert "microsoft.network/azurefirewalls" in SEC_AFW_001["resource_types"]


@pytest.mark.unit
class TestRelAfw001:
    """REL-AFW-001 — Azure Firewall not deployed across Availability Zones."""

    _dsl = REL_AFW_001["condition_dsl"]

    def test_fires_when_zones_null(self) -> None:
        resource = {"properties": {"sku": {"name": "AZFW_VNet", "tier": "Standard"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_zones_empty(self) -> None:
        resource = {"zones": [], "properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_zones_configured(self) -> None:
        resource = {"zones": ["1", "2", "3"], "properties": {"threatIntelMode": "Alert"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_single_zone_configured(self) -> None:
        resource = {"zones": ["2"]}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_AFW_001["rule_id"] == "REL-AFW-001"
        assert REL_AFW_001["pillar"] == "reliability"
        assert "microsoft.network/azurefirewalls" in REL_AFW_001["resource_types"]


# ---------------------------------------------------------------------------
# Container Apps
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecCa001:
    """SEC-CA-001 — Container App ingress allows insecure HTTP."""

    _dsl = SEC_CA_001["condition_dsl"]

    def test_fires_when_allow_insecure_true(self) -> None:
        resource = {
            "properties": {
                "configuration": {"ingress": {"external": True, "allowInsecure": True}}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_allow_insecure_false(self) -> None:
        resource = {
            "properties": {
                "configuration": {"ingress": {"external": True, "allowInsecure": False}}
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_no_ingress(self) -> None:
        """No ingress configured — Not Applicable."""
        resource = {"properties": {"configuration": {}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_allow_insecure_null(self) -> None:
        resource = {"properties": {"configuration": {"ingress": {"external": False}}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_CA_001["rule_id"] == "SEC-CA-001"
        assert SEC_CA_001["pillar"] == "security"
        assert "microsoft.app/containerapps" in SEC_CA_001["resource_types"]


@pytest.mark.unit
class TestRelCa001:
    """REL-CA-001 — Container App minimum replicas = 0."""

    _dsl = REL_CA_001["condition_dsl"]

    def test_fires_when_min_replicas_zero(self) -> None:
        resource = {"properties": {"template": {"scale": {"minReplicas": 0, "maxReplicas": 10}}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_min_replicas_null(self) -> None:
        resource = {"properties": {"template": {"scale": {"maxReplicas": 10}}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_scale_null(self) -> None:
        resource = {"properties": {"template": {}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_min_replicas_one(self) -> None:
        resource = {"properties": {"template": {"scale": {"minReplicas": 1, "maxReplicas": 10}}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_min_replicas_three(self) -> None:
        resource = {"properties": {"template": {"scale": {"minReplicas": 3, "maxReplicas": 10}}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_CA_001["rule_id"] == "REL-CA-001"
        assert REL_CA_001["pillar"] == "reliability"
        assert "microsoft.app/containerapps" in REL_CA_001["resource_types"]


@pytest.mark.unit
class TestOpsCa001:
    """OPS-CA-001 — Container App has no managed identity."""

    _dsl = OPS_CA_001["condition_dsl"]

    def test_fires_when_identity_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_identity_type_none(self) -> None:
        resource = {"identity": {"type": "None"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_system_assigned(self) -> None:
        resource = {"identity": {"type": "SystemAssigned", "principalId": "some-guid"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_user_assigned(self) -> None:
        resource = {
            "identity": {
                "type": "UserAssigned",
                "userAssignedIdentities": {"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1": {}},
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_CA_001["rule_id"] == "OPS-CA-001"
        assert OPS_CA_001["pillar"] == "operational_excellence"
        assert "microsoft.app/containerapps" in OPS_CA_001["resource_types"]


# ---------------------------------------------------------------------------
# Availability Sets
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRelAvset001:
    """REL-AVSET-001 — Availability Set using Classic (unmanaged) mode."""

    _dsl = REL_AVSET_001["condition_dsl"]

    def test_fires_when_sku_null(self) -> None:
        resource = {"properties": {"platformFaultDomainCount": 2}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_sku_classic(self) -> None:
        resource = {"sku": {"name": "Classic"}, "properties": {"platformFaultDomainCount": 2}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_sku_aligned(self) -> None:
        resource = {"sku": {"name": "Aligned"}, "properties": {"platformFaultDomainCount": 2}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_AVSET_001["rule_id"] == "REL-AVSET-001"
        assert REL_AVSET_001["pillar"] == "reliability"
        assert "microsoft.compute/availabilitysets" in REL_AVSET_001["resource_types"]


@pytest.mark.unit
class TestRelAvset002:
    """REL-AVSET-002 — Availability Set fault domain count < 2."""

    _dsl = REL_AVSET_002["condition_dsl"]

    def test_fires_when_fault_domains_one(self) -> None:
        resource = {"properties": {"platformFaultDomainCount": 1}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_fault_domains_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_fault_domains_two(self) -> None:
        resource = {"sku": {"name": "Aligned"}, "properties": {"platformFaultDomainCount": 2}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_fault_domains_three(self) -> None:
        resource = {"sku": {"name": "Aligned"}, "properties": {"platformFaultDomainCount": 3}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_AVSET_002["rule_id"] == "REL-AVSET-002"
        assert REL_AVSET_002["pillar"] == "reliability"
        assert "microsoft.compute/availabilitysets" in REL_AVSET_002["resource_types"]


# ---------------------------------------------------------------------------
# SQL Managed Instance
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecSqlmi001:
    """SEC-SQLMI-001 — SQL MI public data endpoint enabled."""

    _dsl = SEC_SQLMI_001["condition_dsl"]

    def test_fires_when_public_endpoint_enabled(self) -> None:
        resource = {"properties": {"publicDataEndpointEnabled": True}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_public_endpoint_disabled(self) -> None:
        resource = {"properties": {"publicDataEndpointEnabled": False}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_public_endpoint_null(self) -> None:
        """Null defaults to disabled — not a finding."""
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_SQLMI_001["rule_id"] == "SEC-SQLMI-001"
        assert SEC_SQLMI_001["pillar"] == "security"
        assert "microsoft.sql/managedinstances" in SEC_SQLMI_001["resource_types"]


@pytest.mark.unit
class TestSecSqlmi002:
    """SEC-SQLMI-002 — SQL MI minimum TLS version below 1.2."""

    _dsl = SEC_SQLMI_002["condition_dsl"]

    def test_fires_when_tls_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tls_none(self) -> None:
        resource = {"properties": {"minimalTlsVersion": "None"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tls_10(self) -> None:
        resource = {"properties": {"minimalTlsVersion": "1.0"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tls_11(self) -> None:
        resource = {"properties": {"minimalTlsVersion": "1.1"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_tls_12(self) -> None:
        resource = {"properties": {"minimalTlsVersion": "1.2"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_tls_13(self) -> None:
        resource = {"properties": {"minimalTlsVersion": "1.3"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_SQLMI_002["rule_id"] == "SEC-SQLMI-002"
        assert SEC_SQLMI_002["pillar"] == "security"
        assert "microsoft.sql/managedinstances" in SEC_SQLMI_002["resource_types"]


@pytest.mark.unit
class TestRelSqlmi001:
    """REL-SQLMI-001 — SQL MI not zone-redundant."""

    _dsl = REL_SQLMI_001["condition_dsl"]

    def test_fires_when_zone_redundant_false(self) -> None:
        resource = {"properties": {"zoneRedundant": False}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_zone_redundant_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_zone_redundant_true(self) -> None:
        resource = {"properties": {"zoneRedundant": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert REL_SQLMI_001["rule_id"] == "REL-SQLMI-001"
        assert REL_SQLMI_001["pillar"] == "reliability"
        assert "microsoft.sql/managedinstances" in REL_SQLMI_001["resource_types"]


# ---------------------------------------------------------------------------
# Event Grid Topics
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecEg001:
    """SEC-EG-001 — Event Grid topic allows public network access."""

    _dsl = SEC_EG_001["condition_dsl"]

    def test_fires_when_public_access_enabled(self) -> None:
        resource = {"properties": {"publicNetworkAccess": "Enabled"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_public_access_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_public_access_disabled(self) -> None:
        resource = {"properties": {"publicNetworkAccess": "Disabled"}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_EG_001["rule_id"] == "SEC-EG-001"
        assert SEC_EG_001["pillar"] == "security"
        assert "microsoft.eventgrid/topics" in SEC_EG_001["resource_types"]


@pytest.mark.unit
class TestSecEg002:
    """SEC-EG-002 — Event Grid local authentication (SAS) not disabled."""

    _dsl = SEC_EG_002["condition_dsl"]

    def test_fires_when_local_auth_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_local_auth_not_disabled(self) -> None:
        resource = {"properties": {"disableLocalAuth": False}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_local_auth_disabled(self) -> None:
        resource = {"properties": {"disableLocalAuth": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_EG_002["rule_id"] == "SEC-EG-002"
        assert SEC_EG_002["pillar"] == "security"
        assert "microsoft.eventgrid/topics" in SEC_EG_002["resource_types"]


# ---------------------------------------------------------------------------
# Application Insights
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestOpsAi001:
    """OPS-AI-001 — Application Insights using classic (non-workspace-based) mode."""

    _dsl = OPS_AI_001["condition_dsl"]

    def test_fires_when_workspace_resource_id_null(self) -> None:
        resource = {"properties": {"Application_Type": "web"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_workspace_resource_id_set(self) -> None:
        resource = {
            "properties": {
                "WorkspaceResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law1",
                "Application_Type": "web",
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_AI_001["rule_id"] == "OPS-AI-001"
        assert OPS_AI_001["pillar"] == "operational_excellence"
        assert "microsoft.insights/components" in OPS_AI_001["resource_types"]


@pytest.mark.unit
class TestCstAi001:
    """CST-AI-001 — Application Insights retention above 90 days."""

    _dsl = CST_AI_001["condition_dsl"]

    def test_fires_when_retention_180(self) -> None:
        resource = {"properties": {"RetentionInDays": 180}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_retention_365(self) -> None:
        resource = {"properties": {"RetentionInDays": 365}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_retention_90(self) -> None:
        resource = {"properties": {"RetentionInDays": 90}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_retention_30(self) -> None:
        resource = {"properties": {"RetentionInDays": 30}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_retention_null(self) -> None:
        """Null retention uses the default (90 days) — not a finding."""
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert CST_AI_001["rule_id"] == "CST-AI-001"
        assert CST_AI_001["pillar"] == "cost_optimization"
        assert "microsoft.insights/components" in CST_AI_001["resource_types"]


# ---------------------------------------------------------------------------
# Action Groups
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestOpsAg001:
    """OPS-AG-001 — Action Group has no email or webhook receivers."""

    _dsl = OPS_AG_001["condition_dsl"]

    def test_fires_when_both_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_both_empty(self) -> None:
        resource = {"properties": {"emailReceivers": [], "webhookReceivers": []}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_email_receiver_present(self) -> None:
        resource = {
            "properties": {
                "emailReceivers": [{"name": "oncall", "emailAddress": "oncall@example.com"}],
                "webhookReceivers": [],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_webhook_receiver_present(self) -> None:
        resource = {
            "properties": {
                "emailReceivers": [],
                "webhookReceivers": [{"name": "pagerduty", "serviceUri": "https://events.pagerduty.com/v2/enqueue"}],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_both_present(self) -> None:
        resource = {
            "properties": {
                "emailReceivers": [{"name": "eng", "emailAddress": "eng@example.com"}],
                "webhookReceivers": [{"name": "slack", "serviceUri": "https://hooks.slack.com/services/abc"}],
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert OPS_AG_001["rule_id"] == "OPS-AG-001"
        assert OPS_AG_001["pillar"] == "operational_excellence"
        assert "microsoft.insights/actiongroups" in OPS_AG_001["resource_types"]


# ---------------------------------------------------------------------------
# App Service — expanded security
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecApp005:
    """SEC-APP-005 — App Service HTTPS-only not enforced."""

    _dsl = SEC_APP_005["condition_dsl"]

    def test_fires_when_https_only_false(self) -> None:
        resource = {"properties": {"httpsOnly": False}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_https_only_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_https_only_true(self) -> None:
        resource = {"properties": {"httpsOnly": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_APP_005["rule_id"] == "SEC-APP-005"
        assert SEC_APP_005["pillar"] == "security"
        assert "microsoft.web/sites" in SEC_APP_005["resource_types"]


@pytest.mark.unit
class TestSecApp006:
    """SEC-APP-006 — App Service minimum TLS version below 1.2."""

    _dsl = SEC_APP_006["condition_dsl"]

    def test_fires_when_tls_version_null(self) -> None:
        resource = {"properties": {"siteConfig": {}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_site_config_null(self) -> None:
        resource = {"properties": {}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tls_10(self) -> None:
        resource = {"properties": {"siteConfig": {"minTlsVersion": "1.0"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_tls_11(self) -> None:
        resource = {"properties": {"siteConfig": {"minTlsVersion": "1.1"}}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_tls_12(self) -> None:
        resource = {"properties": {"siteConfig": {"minTlsVersion": "1.2"}}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_tls_13(self) -> None:
        resource = {"properties": {"siteConfig": {"minTlsVersion": "1.3"}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_APP_006["rule_id"] == "SEC-APP-006"
        assert SEC_APP_006["pillar"] == "security"
        assert "microsoft.web/sites" in SEC_APP_006["resource_types"]


@pytest.mark.unit
class TestSecApp007:
    """SEC-APP-007 — App Service has no managed identity."""

    _dsl = SEC_APP_007["condition_dsl"]

    def test_fires_when_identity_null(self) -> None:
        resource = {"properties": {"httpsOnly": True}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_identity_type_none(self) -> None:
        resource = {"identity": {"type": "None"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_system_assigned(self) -> None:
        resource = {"identity": {"type": "SystemAssigned", "principalId": "some-guid"}}
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_user_assigned(self) -> None:
        resource = {"identity": {"type": "UserAssigned", "userAssignedIdentities": {}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_APP_007["rule_id"] == "SEC-APP-007"
        assert SEC_APP_007["pillar"] == "security"
        assert "microsoft.web/sites" in SEC_APP_007["resource_types"]


# ---------------------------------------------------------------------------
# Virtual Machines — expanded security
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecVm004:
    """SEC-VM-004 — VM has no managed identity assigned."""

    _dsl = SEC_VM_004["condition_dsl"]

    def test_fires_when_identity_null(self) -> None:
        resource = {"properties": {"hardwareProfile": {"vmSize": "Standard_D4s_v3"}}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_identity_type_none(self) -> None:
        resource = {"identity": {"type": "None"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_system_assigned(self) -> None:
        resource = {
            "identity": {"type": "SystemAssigned", "principalId": "pid", "tenantId": "tid"}
        }
        assert _eval(self._dsl, resource) is False

    def test_no_fire_when_user_assigned(self) -> None:
        resource = {"identity": {"type": "UserAssigned", "userAssignedIdentities": {}}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_VM_004["rule_id"] == "SEC-VM-004"
        assert SEC_VM_004["pillar"] == "security"
        assert "microsoft.compute/virtualmachines" in SEC_VM_004["resource_types"]


# ---------------------------------------------------------------------------
# AKS — expanded security
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSecAks001:
    """SEC-AKS-001 — AKS Kubernetes RBAC not enabled."""

    _dsl = SEC_AKS_001["condition_dsl"]

    def test_fires_when_rbac_false(self) -> None:
        resource = {"properties": {"enableRBAC": False}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_rbac_null(self) -> None:
        resource = {"properties": {"kubernetesVersion": "1.28.0"}}
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_rbac_enabled(self) -> None:
        resource = {"properties": {"enableRBAC": True}}
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_AKS_001["rule_id"] == "SEC-AKS-001"
        assert SEC_AKS_001["pillar"] == "security"
        assert "microsoft.containerservice/managedclusters" in SEC_AKS_001["resource_types"]


@pytest.mark.unit
class TestSecAks002:
    """SEC-AKS-002 — AKS API server publicly accessible."""

    _dsl = SEC_AKS_002["condition_dsl"]

    def test_fires_when_private_cluster_null(self) -> None:
        resource = {"properties": {"kubernetesVersion": "1.28.0"}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_api_server_profile_null(self) -> None:
        resource = {"properties": {"enableRBAC": True}}
        assert _eval(self._dsl, resource) is True

    def test_fires_when_private_cluster_false(self) -> None:
        resource = {
            "properties": {
                "apiServerAccessProfile": {"enablePrivateCluster": False}
            }
        }
        assert _eval(self._dsl, resource) is True

    def test_no_fire_when_private_cluster_true(self) -> None:
        resource = {
            "properties": {
                "apiServerAccessProfile": {
                    "enablePrivateCluster": True,
                    "privateDNSZone": "system",
                }
            }
        }
        assert _eval(self._dsl, resource) is False

    def test_metadata(self) -> None:
        assert SEC_AKS_002["rule_id"] == "SEC-AKS-002"
        assert SEC_AKS_002["pillar"] == "security"
        assert "microsoft.containerservice/managedclusters" in SEC_AKS_002["resource_types"]
