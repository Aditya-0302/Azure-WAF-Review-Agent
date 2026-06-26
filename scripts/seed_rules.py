#!/usr/bin/env python3
"""WAF Rule Catalog Seed Script.

Upserts all WAF rule definitions (existing + Phase 3 new rules) into the
``waf_rules`` PostgreSQL table via WafRuleRepository.  Idempotent: safe to
run multiple times; ON CONFLICT(rule_id) updates the existing row and
increments the version counter.

Usage
-----
  python scripts/seed_rules.py [--dry-run] [--pillar <pillar>]

Environment variables required (same as AgentSettings):
  DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

The script exits 0 on success, 1 on any error.

Helm integration: this script is invoked by the ``seed-rules-post-upgrade-hook``
Kubernetes Job after every Helm upgrade so the database rule catalogue stays
in sync with the code.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

# ── Path bootstrap ────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
for _pkg in ["src/shared"]:
    _p = _ROOT / _pkg
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# ── Imports (after path bootstrap) ───────────────────────────────────────────
import asyncpg  # noqa: E402
from pydantic import Field, SecretStr  # noqa: E402
from pydantic_settings import BaseSettings, SettingsConfigDict  # noqa: E402

from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule  # noqa: E402
from waf_catalog.rule_definitions import NEW_RULES, NEWLY_COVERED_CONTROLS, HUMAN_REVIEW_REQUIRED  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal settings — DB only, no Azure auth required
# ---------------------------------------------------------------------------

class SeederSettings(BaseSettings):
    """Database-only settings for the rule-seeding script.

    Does NOT inherit AgentSettings and has NO Azure auth validation.
    The seed script only writes static rule rows into PostgreSQL.
    """

    model_config = SettingsConfigDict(
        env_file=None,
        case_sensitive=False,
        extra="ignore",
    )

    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "wafagent"
    db_user: str = "wafagent"
    db_password: SecretStr = SecretStr("changeme")

    @property
    def dsn_primary(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )


# ---------------------------------------------------------------------------
# Existing rule catalogue (all 78 original rules)
# ---------------------------------------------------------------------------
# Rules are defined inline here as dicts; upsert is idempotent so any already-
# existing row is updated in-place (version += 1).  The full set is included
# so a fresh database can be seeded from a single script execution.

_PILLAR_MAP: dict[str, str] = {
    "SEC": "security",
    "REL": "reliability",
    "CST": "cost_optimization",
    "OPS": "operational_excellence",
    "PER": "performance_efficiency",
    "STOR": "security",
}


def _existing_rule(
    rule_id: str,
    pillar: str,
    resource_types: list[str],
    evaluation_type: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    condition_dsl=None,
    prompt_template_ref: str | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "pillar": pillar,
        "resource_types": resource_types,
        "evaluation_type": evaluation_type,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "condition_dsl": condition_dsl,
        "prompt_template_ref": prompt_template_ref,
        "is_active": True,
        "version": 1,
    }


EXISTING_RULES: list[dict] = [
    # ── Key Vault ────────────────────────────────────────────────────────────
    _existing_rule("SEC-KV-001", "security",
        ["microsoft.keyvault/vaults"], "deterministic", "high",
        "Key Vault soft delete is disabled",
        "Key Vault soft delete prevents permanent accidental deletion of secrets, keys, and certificates.",
        "Enable soft delete: az keyvault update --name <kv> --enable-soft-delete true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.enableSoftDelete", "value": True}}),
    _existing_rule("SEC-KV-002", "security",
        ["microsoft.keyvault/vaults"], "deterministic", "high",
        "Key Vault purge protection is disabled",
        "Purge protection prevents malicious or accidental permanent deletion during the retention period.",
        "Enable purge protection: az keyvault update --name <kv> --enable-purge-protection true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.enablePurgeProtection", "value": True}}),
    _existing_rule("SEC-KV-003", "security",
        ["microsoft.keyvault/vaults"], "deterministic", "medium",
        "Key Vault is not using private endpoint",
        "Public network access to Key Vault exposes secrets to internet-routable paths.",
        "Add a private endpoint to the Key Vault and disable public access.",
        {"op": "ne", "path": "properties.publicNetworkAccess", "value": "Disabled"}),
    _existing_rule("SEC-KV-004", "security",
        ["microsoft.keyvault/vaults"], "deterministic", "medium",
        "Key Vault RBAC authorization is not enabled",
        "Vault access policies are less granular than Azure RBAC and harder to audit.",
        "Migrate to RBAC: az keyvault update --name <kv> --enable-rbac-authorization true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.enableRbacAuthorization", "value": True}}),
    _existing_rule("SEC-KV-005", "security",
        ["microsoft.keyvault/vaults"], "deterministic", "medium",
        "Key Vault network ACLs allow unrestricted access",
        "Without network ACLs the Key Vault is reachable from any public IP address.",
        "Configure network ACLs with an 'Deny' default action and explicit allow rules for trusted CIDRs or VNets.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "properties.networkAcls"},
            {"op": "eq", "path": "properties.networkAcls.defaultAction", "value": "Allow"},
        ]}),

    # ── Storage ───────────────────────────────────────────────────────────────
    _existing_rule("SEC-STOR-001", "security",
        ["microsoft.storage/storageaccounts"], "deterministic", "high",
        "Storage account allows public blob access",
        "Public blob access enables anonymous read of blobs without authentication.",
        "Disable public blob access: az storage account update --name <sa> --allow-blob-public-access false",
        {"op": "bool_eq", "path": "properties.allowBlobPublicAccess", "value": True}),
    _existing_rule("SEC-STOR-002", "security",
        ["microsoft.storage/storageaccounts"], "deterministic", "high",
        "Storage account does not enforce HTTPS-only traffic",
        "HTTP traffic is unencrypted; all data in transit must be encrypted.",
        "Enable HTTPS only: az storage account update --name <sa> --https-only true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.supportsHttpsTrafficOnly", "value": True}}),
    _existing_rule("SEC-STOR-003", "security",
        ["microsoft.storage/storageaccounts"], "deterministic", "medium",
        "Storage account minimum TLS version is below 1.2",
        "TLS 1.0 and 1.1 have known vulnerabilities. TLS 1.2 is the minimum acceptable.",
        "Set minimum TLS version: az storage account update --name <sa> --min-tls-version TLS1_2",
        {"op": "in", "path": "properties.minimumTlsVersion", "value": ["TLS1_0", "TLS1_1"]}),
    _existing_rule("SEC-STOR-004", "security",
        ["microsoft.storage/storageaccounts"], "deterministic", "medium",
        "Storage account shared key access is not disabled",
        "Shared key authentication is less secure than Azure AD-based authentication.",
        "Disable shared key access and use Azure AD RBAC instead.",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.allowSharedKeyAccess", "value": False}}),
    _existing_rule("SEC-STOR-005", "security",
        ["microsoft.storage/storageaccounts"], "deterministic", "low",
        "Storage account infrastructure encryption is not enabled",
        "Infrastructure encryption adds a second layer of AES-256 encryption at rest.",
        "Enable infrastructure encryption at account creation time (cannot be changed later).",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.encryption.requireInfrastructureEncryption", "value": True}}),

    # ── Network ───────────────────────────────────────────────────────────────
    _existing_rule("SEC-NET-001", "security",
        ["microsoft.network/networksecuritygroups"], "deterministic", "high",
        "NSG allows unrestricted SSH inbound from the internet",
        "Unrestricted SSH (port 22) from 0.0.0.0/0 enables brute-force attacks.",
        "Restrict SSH source to known management IPs or use Azure Bastion.",
        {"op": "any_match", "path": "properties.securityRules", "condition": {"op": "and", "conditions": [
            {"op": "eq", "path": "properties.destinationPortRange", "value": "22"},
            {"op": "eq", "path": "properties.sourceAddressPrefix", "value": "*"},
            {"op": "eq", "path": "properties.access", "value": "Allow"},
            {"op": "eq", "path": "properties.direction", "value": "Inbound"},
        ]}}),
    _existing_rule("SEC-NET-002", "security",
        ["microsoft.network/networksecuritygroups"], "deterministic", "high",
        "NSG allows unrestricted RDP inbound from the internet",
        "Unrestricted RDP (port 3389) exposes Windows machines to brute-force attacks.",
        "Restrict RDP source to known IPs or use Azure Bastion / Just-In-Time VM access.",
        {"op": "any_match", "path": "properties.securityRules", "condition": {"op": "and", "conditions": [
            {"op": "eq", "path": "properties.destinationPortRange", "value": "3389"},
            {"op": "eq", "path": "properties.sourceAddressPrefix", "value": "*"},
            {"op": "eq", "path": "properties.access", "value": "Allow"},
            {"op": "eq", "path": "properties.direction", "value": "Inbound"},
        ]}}),
    _existing_rule("SEC-NET-003", "security",
        ["microsoft.network/networksecuritygroups"], "deterministic", "medium",
        "NSG has no explicit deny-all inbound rule",
        "Without an explicit deny-all, traffic to unlisted ports may be allowed by Azure's default rules.",
        "Add a deny-all inbound rule at priority 4096.",
        {"op": "not", "condition": {"op": "any_match", "path": "properties.securityRules", "condition": {"op": "and", "conditions": [
            {"op": "eq", "path": "properties.sourceAddressPrefix", "value": "*"},
            {"op": "eq", "path": "properties.destinationPortRange", "value": "*"},
            {"op": "eq", "path": "properties.access", "value": "Deny"},
            {"op": "eq", "path": "properties.direction", "value": "Inbound"},
        ]}}}),

    # ── SQL ───────────────────────────────────────────────────────────────────
    _existing_rule("SEC-SQL-001", "security",
        ["microsoft.sql/servers"], "deterministic", "high",
        "SQL Server allows public network access",
        "A public endpoint on the SQL Server exposes it to internet-sourced attacks.",
        "Disable public network access and use private endpoints.",
        {"op": "ne", "path": "properties.publicNetworkAccess", "value": "Disabled"}),
    _existing_rule("SEC-SQL-002", "security",
        ["microsoft.sql/servers/databases"], "deterministic", "high",
        "SQL Database Transparent Data Encryption is not enabled",
        "TDE encrypts data at rest, protecting against offline disk theft.",
        "Enable TDE: az sql db tde set --status Enabled -s <server> -d <db> -g <rg>",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "properties.transparentDataEncryption"},
            {"op": "ne", "path": "properties.transparentDataEncryption.status", "value": "Enabled"},
        ]}),
    _existing_rule("SEC-SQL-003", "security",
        ["microsoft.sql/servers"], "deterministic", "medium",
        "SQL Server Azure AD-only authentication is not enforced",
        "SQL authentication uses passwords; Azure AD auth provides MFA and conditional access.",
        "Enable Azure AD-only auth: az sql server ad-only-auth enable -n <server> -g <rg>",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.administrators.azureADOnlyAuthentication", "value": True}}),
    _existing_rule("SEC-SQL-004", "security",
        ["microsoft.sql/servers"], "deterministic", "medium",
        "SQL Server auditing is not enabled",
        "Auditing logs all SQL activity for compliance and threat detection.",
        "Enable auditing: az sql server audit-policy update -n <server> -g <rg> --state Enabled",
        {"op": "ne", "path": "properties.auditingSettings.state", "value": "Enabled"}),

    # ── VM ────────────────────────────────────────────────────────────────────
    _existing_rule("SEC-VM-001", "security",
        ["microsoft.compute/virtualmachines"], "deterministic", "high",
        "VM disk encryption is not enabled",
        "Unencrypted OS and data disks are readable if the physical media is stolen.",
        "Enable Azure Disk Encryption or use Server-Side Encryption with CMK.",
        {"op": "is_null", "path": "properties.storageProfile.osDisk.encryptionSettings"}),
    _existing_rule("SEC-VM-002", "security",
        ["microsoft.compute/virtualmachines"], "deterministic", "high",
        "VM has a public IP address directly attached",
        "A public IP directly on a VM exposes all open ports to the internet.",
        "Remove the public IP; use Azure Bastion or a load balancer with limited port exposure.",
        {"op": "any_match", "path": "properties.networkProfile.networkInterfaces", "condition": {
            "op": "exists", "path": "properties.ipConfigurations[0].properties.publicIPAddress"
        }}),
    _existing_rule("SEC-VM-003", "security",
        ["microsoft.compute/virtualmachines"], "deterministic", "medium",
        "VM is not using managed identity",
        "Without a managed identity the VM cannot authenticate to Azure services without stored credentials.",
        "Assign a system-assigned or user-assigned managed identity to the VM.",
        {"op": "is_null", "path": "identity"}),

    # ── App Service ───────────────────────────────────────────────────────────
    _existing_rule("SEC-APP-001", "security",
        ["microsoft.web/sites"], "deterministic", "high",
        "App Service does not enforce HTTPS-only",
        "HTTP traffic is unencrypted; HTTPS-only must be enforced.",
        "Enable HTTPS only: az webapp update --name <app> -g <rg> --set httpsOnly=true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.httpsOnly", "value": True}}),
    _existing_rule("SEC-APP-002", "security",
        ["microsoft.web/sites"], "deterministic", "medium",
        "App Service minimum TLS version is below 1.2",
        "TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.",
        "Set minimum TLS 1.2: az webapp config set --name <app> -g <rg> --min-tls-version 1.2",
        {"op": "in", "path": "properties.siteConfig.minTlsVersion", "value": ["1.0", "1.1"]}),
    _existing_rule("SEC-APP-003", "security",
        ["microsoft.web/sites"], "deterministic", "medium",
        "App Service client certificates (mutual TLS) are not required",
        "mTLS validates the identity of API clients calling the App Service.",
        "Enable client certificates: az webapp update --name <app> -g <rg> --client-affinity-enabled true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.clientCertEnabled", "value": True}}),
    _existing_rule("SEC-APP-004", "security",
        ["microsoft.web/sites"], "deterministic", "low",
        "App Service has no IP access restrictions configured",
        "Without IP restrictions, the app is accessible from any IP address.",
        "Add IP access restriction rules to limit access to known CIDRs.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "properties.siteConfig.ipSecurityRestrictions"},
            {"op": "length_eq", "path": "properties.siteConfig.ipSecurityRestrictions", "value": 0},
        ]}),

    # ── RBAC ─────────────────────────────────────────────────────────────────
    _existing_rule("SEC-RBAC-001", "security",
        ["*"], "deterministic", "medium",
        "Resource has a classic co-administrator or service administrator role assignment",
        "Classic roles are deprecated and bypass Azure RBAC controls.",
        "Remove classic role assignments and use Azure RBAC equivalents.",
        {"op": "any_match", "path": "properties.roleAssignments", "condition": {
            "op": "in", "path": "properties.roleDefinitionId",
            "value": ["CoAdministrator", "ServiceAdministrator"],
        }}),
    _existing_rule("SEC-RBAC-002", "security",
        ["*"], "llm", "medium",
        "Resource has overly broad RBAC role assignment (Owner or Contributor at scope)",
        "Owner/Contributor at broad scope violates least-privilege access (SE-05, SE-08).",
        "Replace broad role assignments with narrowly scoped custom roles.",
        None, "llm-rbac-broad-assignment"),

    # ── Reliability — VM ──────────────────────────────────────────────────────
    _existing_rule("REL-VM-001", "reliability",
        ["microsoft.compute/virtualmachines"], "deterministic", "high",
        "VM is not in an Availability Zone",
        "VMs not in zones have no SLA protection against datacenter-level failures.",
        "Deploy VMs across Availability Zones or use a VMSS with zone spreading.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "zones"},
            {"op": "length_eq", "path": "zones", "value": 0},
        ]}),
    _existing_rule("REL-VM-002", "reliability",
        ["microsoft.compute/virtualmachines"], "deterministic", "high",
        "VM is not in an Availability Set or Zone",
        "Without an availability set or zone, there is no guaranteed uptime SLA for multiple VMs.",
        "Place VMs in an Availability Set or deploy to multiple Availability Zones.",
        {"op": "and", "conditions": [
            {"op": "or", "conditions": [
                {"op": "is_null", "path": "zones"},
                {"op": "length_eq", "path": "zones", "value": 0},
            ]},
            {"op": "is_null", "path": "properties.availabilitySet"},
        ]}),
    _existing_rule("REL-VM-003", "reliability",
        ["microsoft.compute/virtualmachines"], "deterministic", "medium",
        "VM OS disk does not use Premium SSD",
        "Standard HDD and Standard SSD have lower durability SLAs than Premium SSD.",
        "Upgrade OS disk to Premium SSD for production VMs.",
        {"op": "in", "path": "properties.storageProfile.osDisk.managedDisk.storageAccountType",
         "value": ["Standard_LRS", "StandardSSD_LRS"]}),
    _existing_rule("REL-VM-004", "reliability",
        ["microsoft.compute/virtualmachines"], "deterministic", "medium",
        "VM does not have accelerated networking enabled",
        "Without accelerated networking, network throughput and latency are suboptimal.",
        "Enable accelerated networking on the VM NIC.",
        {"op": "not", "condition": {"op": "bool_eq",
         "path": "properties.networkProfile.networkInterfaces[0].properties.enableAcceleratedNetworking",
         "value": True}}),

    # ── Reliability — VMSS ────────────────────────────────────────────────────
    _existing_rule("REL-VMSS-001", "reliability",
        ["microsoft.compute/virtualmachinescalesets"], "deterministic", "high",
        "VMSS is not zone-redundant",
        "A non-zone-redundant VMSS has no protection against a zone failure.",
        "Set zones: [1, 2, 3] on the VMSS configuration.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "zones"},
            {"op": "length_eq", "path": "zones", "value": 0},
        ]}),
    _existing_rule("REL-VMSS-002", "reliability",
        ["microsoft.compute/virtualmachinescalesets"], "deterministic", "medium",
        "VMSS overprovisioning is disabled",
        "Overprovisioning improves scaling reliability by creating extra VMs during scale-out.",
        "Enable overprovisioning: set overprovision: true in the VMSS configuration.",
        {"op": "bool_eq", "path": "properties.overprovision", "value": False}),

    # ── Reliability — App Service ─────────────────────────────────────────────
    _existing_rule("REL-APP-001", "reliability",
        ["microsoft.web/serverfarms"], "deterministic", "high",
        "App Service plan has only one instance (no redundancy)",
        "A single-instance plan has no redundancy; any restart causes downtime.",
        "Set minimum instance count to 2: az appservice plan update --name <plan> -g <rg> --number-of-workers 2",
        {"op": "lte", "path": "sku.capacity", "value": 1}),
    _existing_rule("REL-APP-002", "reliability",
        ["microsoft.web/sites"], "deterministic", "medium",
        "App Service does not have Always On enabled",
        "Without Always On, the app may go cold and fail to respond to initial requests.",
        "Enable Always On: az webapp config set --name <app> -g <rg> --always-on true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.siteConfig.alwaysOn", "value": True}}),
    _existing_rule("REL-APP-003", "reliability",
        ["microsoft.web/sites"], "deterministic", "medium",
        "App Service health check is not configured",
        "Without health checks, the platform cannot automatically replace unhealthy instances.",
        "Configure a health check path: az webapp config set --name <app> -g <rg> --generic-configurations '{\"healthCheckPath\":\"/health\"}'",
        {"op": "is_null", "path": "properties.siteConfig.healthCheckPath"}),

    # ── Reliability — SQL ─────────────────────────────────────────────────────
    _existing_rule("REL-SQL-001", "reliability",
        ["microsoft.sql/servers/databases"], "deterministic", "high",
        "SQL Database is not using geo-redundant backup storage",
        "Local backup storage only provides protection within a single region.",
        "Set backup storage redundancy to Geo: az sql db update -s <server> -d <db> -g <rg> --backup-storage-redundancy Geo",
        {"op": "ne", "path": "properties.requestedBackupStorageRedundancy", "value": "Geo"}),
    _existing_rule("REL-SQL-002", "reliability",
        ["microsoft.sql/servers/databases"], "deterministic", "medium",
        "SQL Database zone redundancy is not enabled",
        "Zone redundancy spreads replicas across Availability Zones for datacenter-level resilience.",
        "Enable zone redundancy: az sql db update -s <server> -d <db> -g <rg> --zone-redundant true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.zoneRedundant", "value": True}}),

    # ── Reliability — Storage ─────────────────────────────────────────────────
    _existing_rule("REL-STOR-001", "reliability",
        ["microsoft.storage/storageaccounts"], "deterministic", "high",
        "Storage account does not use geo-redundant replication",
        "LRS replication only protects against rack failures, not regional outages.",
        "Upgrade to GRS or RA-GRS: az storage account update --name <sa> -g <rg> --sku Standard_GRS",
        {"op": "in", "path": "sku.name", "value": ["Standard_LRS", "Premium_LRS"]}),
    _existing_rule("REL-STOR-002", "reliability",
        ["microsoft.storage/storageaccounts"], "deterministic", "medium",
        "Storage account does not have soft delete enabled for blobs",
        "Without soft delete, deleted blobs cannot be recovered.",
        "Enable blob soft delete with a 14-day retention period.",
        {"op": "not", "condition": {"op": "bool_eq",
         "path": "properties.blobServiceProperties.deleteRetentionPolicy.enabled", "value": True}}),
    _existing_rule("REL-STOR-003", "reliability",
        ["microsoft.storage/storageaccounts"], "deterministic", "low",
        "Storage account does not have point-in-time restore enabled",
        "Point-in-time restore allows recovery of blob data to any point within the retention period.",
        "Enable point-in-time restore: set restorePolicy.enabled=true on the blob service.",
        {"op": "not", "condition": {"op": "bool_eq",
         "path": "properties.blobServiceProperties.restorePolicy.enabled", "value": True}}),

    # ── Reliability — Load Balancer / AGW ─────────────────────────────────────
    _existing_rule("REL-LB-001", "reliability",
        ["microsoft.network/loadbalancers"], "deterministic", "high",
        "Load balancer is not zone-redundant",
        "A non-zone-redundant load balancer is a single point of failure at the zone level.",
        "Use a Standard SKU load balancer with zone-redundant frontend IP.",
        {"op": "eq", "path": "sku.name", "value": "Basic"}),
    _existing_rule("REL-AGW-001", "reliability",
        ["microsoft.network/applicationgateways"], "deterministic", "medium",
        "Application Gateway autoscale is not configured",
        "Without autoscale, the gateway cannot handle traffic spikes without manual intervention.",
        "Configure autoscale: set autoscaleConfiguration.minCapacity and maxCapacity.",
        {"op": "is_null", "path": "properties.autoscaleConfiguration"}),
    _existing_rule("REL-ARC-001", "reliability",
        ["*"], "advisor_mapped", "medium",
        "Azure Advisor reliability recommendation detected",
        "Azure Advisor reliability recommendations indicate resource configuration gaps.",
        "Review and action the Advisor reliability recommendation.",
        None, "advisor-reliability-general"),

    # ── Cost Optimization ─────────────────────────────────────────────────────
    _existing_rule("CST-VM-001", "cost_optimization",
        ["microsoft.compute/virtualmachines"], "deterministic", "medium",
        "VM is deallocated but still billed for disk storage",
        "A stopped (deallocated) VM still incurs disk costs. Delete if unused.",
        "Review and delete unused VMs and their disks.",
        {"op": "eq", "path": "properties.extended.instanceView.powerState.code", "value": "PowerState/deallocated"}),
    _existing_rule("CST-VM-002", "cost_optimization",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "low",
        "VM reserved instance opportunity identified by Azure Advisor",
        "Advisor identifies VMs with stable workloads that could save cost with reserved instances.",
        "Purchase Reserved Instances for stable, always-on VMs.",
        None, "advisor-cost-reservations"),
    _existing_rule("CST-VM-003", "cost_optimization",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "medium",
        "VM is over-provisioned — right-size recommended by Azure Advisor",
        "Advisor analyses CPU and memory utilisation to identify over-provisioned VMs.",
        "Right-size or shut down the VM per Advisor recommendation.",
        None, "advisor-cost-rightsize"),
    _existing_rule("CST-DISK-001", "cost_optimization",
        ["microsoft.compute/disks"], "deterministic", "low",
        "Managed disk is unattached (orphaned)",
        "Unattached managed disks incur storage costs without providing value.",
        "Delete the disk: az disk delete --name <disk> -g <rg>",
        {"op": "is_null", "path": "managedBy"}),
    _existing_rule("CST-DISK-002", "cost_optimization",
        ["microsoft.compute/disks"], "advisor_mapped", "low",
        "Disk SKU can be downgraded per Azure Advisor recommendation",
        "Premium SSD may be over-provisioned for disks with low I/O.",
        "Downgrade to Standard SSD or Standard HDD if I/O requirements allow.",
        None, "advisor-cost-disk-sku"),
    _existing_rule("CST-IP-001", "cost_optimization",
        ["microsoft.network/publicipaddresses"], "deterministic", "low",
        "Public IP address is not associated with any resource",
        "Unassociated public IPs incur ongoing charges without providing value.",
        "Delete the public IP or associate it with a resource.",
        {"op": "is_null", "path": "properties.ipConfiguration"}),
    _existing_rule("CST-LB-001", "cost_optimization",
        ["microsoft.network/loadbalancers"], "deterministic", "low",
        "Load balancer has no backend pool instances",
        "An empty load balancer incurs charges without serving traffic.",
        "Delete the load balancer or add backend instances.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "properties.backendAddressPools"},
            {"op": "length_eq", "path": "properties.backendAddressPools", "value": 0},
        ]}),
    _existing_rule("CST-AGW-001", "cost_optimization",
        ["microsoft.network/applicationgateways"], "advisor_mapped", "medium",
        "Application Gateway right-sizing opportunity identified",
        "Advisor identifies underutilised Application Gateways.",
        "Right-size or consolidate Application Gateways per Advisor recommendation.",
        None, "advisor-cost-agw"),
    _existing_rule("CST-SQL-001", "cost_optimization",
        ["microsoft.sql/servers/databases"], "advisor_mapped", "medium",
        "SQL Database right-sizing or elastic pool opportunity",
        "Advisor identifies SQL databases that could save cost by moving to elastic pools.",
        "Evaluate elastic pool membership for the SQL database.",
        None, "advisor-cost-sql"),
    _existing_rule("CST-STOR-001", "cost_optimization",
        ["microsoft.storage/storageaccounts"], "deterministic", "low",
        "Storage account is using Hot tier for infrequently accessed data",
        "Hot tier costs more per GB stored; Cool or Archive tier is cheaper for cold data.",
        "Enable lifecycle management to automatically tier blobs to Cool/Archive.",
        {"op": "eq", "path": "properties.accessTier", "value": "Hot"}),
    _existing_rule("CST-STOR-002", "cost_optimization",
        ["microsoft.storage/storageaccounts"], "advisor_mapped", "low",
        "Storage account cost optimisation opportunity identified by Advisor",
        "Advisor identifies storage accounts with lifecycle management opportunities.",
        "Enable lifecycle management rules to move cold blobs to cheaper tiers.",
        None, "advisor-cost-storage"),

    # ── Operational Excellence ────────────────────────────────────────────────
    _existing_rule("OPS-VM-001", "operational_excellence",
        ["microsoft.compute/virtualmachines"], "deterministic", "medium",
        "VM operating system image is not using a recent supported version",
        "Outdated OS versions may be missing security patches and operational tooling.",
        "Update the VM image to a current supported OS version.",
        {"op": "contains", "path": "properties.storageProfile.imageReference.sku",
         "value": "2012", "ci": True}),
    _existing_rule("OPS-VM-002", "operational_excellence",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "medium",
        "VM OS patch management is not configured",
        "Without automated patching, OS updates are applied inconsistently.",
        "Enable Automatic VM Guest Patching via Azure Update Manager.",
        None, "advisor-ops-patching"),
    _existing_rule("OPS-APP-001", "operational_excellence",
        ["microsoft.web/sites"], "deterministic", "low",
        "App Service is running on a deprecated runtime version",
        "End-of-life runtime versions receive no security patches.",
        "Update the runtime to a current supported version in App Service configuration.",
        {"op": "or", "conditions": [
            {"op": "contains", "path": "properties.siteConfig.netFrameworkVersion", "value": "v2.", "ci": True},
            {"op": "contains", "path": "properties.siteConfig.phpVersion", "value": "5.", "ci": True},
        ]}),
    _existing_rule("OPS-APP-002", "operational_excellence",
        ["microsoft.web/sites"], "deterministic", "low",
        "App Service remote debugging is enabled",
        "Remote debugging should never be enabled in production environments.",
        "Disable remote debugging: az webapp config set --name <app> -g <rg> --remote-debugging-enabled false",
        {"op": "bool_eq", "path": "properties.siteConfig.remoteDebuggingEnabled", "value": True}),
    _existing_rule("OPS-KV-001", "operational_excellence",
        ["microsoft.keyvault/vaults"], "deterministic", "low",
        "Key Vault soft delete retention period is less than 14 days",
        "A short retention window reduces the recovery time available after accidental deletion.",
        "Set softDeleteRetentionInDays to at least 14 for production Key Vaults.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "properties.softDeleteRetentionInDays"},
            {"op": "lt", "path": "properties.softDeleteRetentionInDays", "value": 14},
        ]}),
    _existing_rule("OPS-SQL-001", "operational_excellence",
        ["microsoft.sql/servers"], "advisor_mapped", "medium",
        "SQL Server has no Azure Defender for SQL enabled",
        "Defender for SQL detects anomalous activity and provides Advanced Threat Protection.",
        "Enable Defender for SQL: az security pricing create --name SqlServers --tier Standard",
        None, "advisor-ops-sql-defender"),
    _existing_rule("OPS-SQL-002", "operational_excellence",
        ["microsoft.sql/servers/databases"], "advisor_mapped", "low",
        "SQL Database long-term backup retention is not configured",
        "Default retention is 7–35 days; regulatory compliance may require years of retention.",
        "Configure long-term retention policy for the SQL database.",
        None, "advisor-ops-sql-backup"),
    _existing_rule("OPS-TAG-001", "operational_excellence",
        ["*"], "deterministic", "low",
        "Resource is missing required operational tags",
        "Tags like Environment, Owner, and Application are required for resource management.",
        "Apply mandatory tags via Azure Policy and tag the resource.",
        {"op": "or", "conditions": [
            {"op": "is_null", "path": "tags.Environment"},
            {"op": "is_null", "path": "tags.Owner"},
        ]}),
    _existing_rule("OPS-LOCK-001", "operational_excellence",
        ["*"], "deterministic", "low",
        "Production resource has no resource lock",
        "Without a CanNotDelete or ReadOnly lock, resources can be accidentally deleted.",
        "Apply a CanNotDelete lock: az lock create --name DoNotDelete --resource-group <rg> --lock-type CanNotDelete",
        {"op": "is_null", "path": "managementLocks"}),
    _existing_rule("OPS-POL-001", "operational_excellence",
        ["*"], "advisor_mapped", "low",
        "Azure Policy non-compliance detected on resource",
        "Policy non-compliance indicates the resource deviates from organisational standards.",
        "Review and remediate the Azure Policy non-compliance.",
        None, "advisor-ops-policy"),
    _existing_rule("OPS-UPD-001", "operational_excellence",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "medium",
        "VM update management is not configured",
        "Without update management, OS and application patches are applied inconsistently.",
        "Enrol the VM in Azure Update Manager.",
        None, "advisor-ops-update-management"),

    # ── Performance Efficiency ────────────────────────────────────────────────
    _existing_rule("PER-VM-001", "performance_efficiency",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "medium",
        "VM CPU utilisation exceeds recommended threshold",
        "Consistent high CPU utilisation degrades application performance and reliability.",
        "Right-size the VM to a higher CPU SKU or enable autoscale.",
        None, "advisor-performance-cpu"),
    _existing_rule("PER-VM-002", "performance_efficiency",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "medium",
        "VM memory utilisation exceeds recommended threshold",
        "High memory pressure causes swapping and performance degradation.",
        "Right-size the VM to a memory-optimised SKU.",
        None, "advisor-performance-memory"),
    _existing_rule("PER-VM-003", "performance_efficiency",
        ["microsoft.compute/virtualmachines"], "deterministic", "medium",
        "VM does not have proximity placement group configured for latency-sensitive workloads",
        "Without proximity placement, related VMs may be placed in different racks, increasing network latency.",
        "Place latency-sensitive VM clusters in a Proximity Placement Group.",
        {"op": "is_null", "path": "properties.proximityPlacementGroup"}),
    _existing_rule("PER-VMSS-001", "performance_efficiency",
        ["microsoft.compute/virtualmachinescalesets"], "deterministic", "medium",
        "VMSS autoscale profile is not configured",
        "Without autoscale, the VMSS cannot respond to load changes automatically.",
        "Configure autoscale settings for the VMSS.",
        {"op": "is_null", "path": "properties.autoscaleSettings"}),
    _existing_rule("PER-VMSS-002", "performance_efficiency",
        ["microsoft.compute/virtualmachinescalesets"], "deterministic", "low",
        "VMSS does not use predictive autoscale",
        "Predictive autoscale uses ML to scale out before demand spikes, improving responsiveness.",
        "Enable predictive autoscale in the autoscale settings.",
        {"op": "ne", "path": "properties.predictiveAutoscalePolicy.scaleMode", "value": "Enabled"}),
    _existing_rule("PER-APP-001", "performance_efficiency",
        ["microsoft.web/serverfarms"], "deterministic", "medium",
        "App Service plan does not have autoscale configured",
        "Without autoscale the plan cannot scale out to handle traffic spikes.",
        "Configure autoscale rules for the App Service plan.",
        {"op": "is_null", "path": "properties.autoscaleSettings"}),
    _existing_rule("PER-APP-002", "performance_efficiency",
        ["microsoft.web/sites"], "deterministic", "low",
        "App Service HTTP/2 is not enabled",
        "HTTP/2 provides multiplexing and header compression for improved performance.",
        "Enable HTTP/2: az webapp config set --name <app> -g <rg> --http20-enabled true",
        {"op": "not", "condition": {"op": "bool_eq", "path": "properties.siteConfig.http20Enabled", "value": True}}),
    _existing_rule("PER-APP-003", "performance_efficiency",
        ["microsoft.web/sites"], "deterministic", "low",
        "App Service ARR affinity cookie is enabled",
        "ARR affinity routes all requests from a session to the same instance, preventing true horizontal scaling.",
        "Disable ARR affinity: az webapp update --name <app> -g <rg> --client-affinity-enabled false",
        {"op": "bool_eq", "path": "properties.clientAffinityEnabled", "value": True}),
    _existing_rule("PER-SQL-001", "performance_efficiency",
        ["microsoft.sql/servers/databases"], "advisor_mapped", "medium",
        "SQL Database performance degradation detected by Advisor",
        "Advisor identifies missing indexes, poor query plans, and other performance issues.",
        "Review Advisor performance recommendations for the SQL database.",
        None, "advisor-performance-sql"),
    _existing_rule("PER-CDN-001", "performance_efficiency",
        ["microsoft.cdn/profiles"], "deterministic", "medium",
        "CDN profile has no custom rules or caching overrides configured",
        "Without caching rules, content is not effectively served from edge nodes.",
        "Configure caching rules to cache static content at the CDN edge.",
        {"op": "is_null", "path": "properties.deliveryPolicy"}),
    _existing_rule("PER-CACHE-001", "performance_efficiency",
        ["microsoft.cache/redis"], "deterministic", "medium",
        "Redis Cache does not have geo-replication configured",
        "Without geo-replication, the cache is a single-region resource with no DR capability.",
        "Enable geo-replication for the Redis Cache (Premium tier required).",
        {"op": "is_null", "path": "properties.linkedServers"}),
    _existing_rule("STOR-TLS-001", "security",
        ["microsoft.storage/storageaccounts"], "deterministic", "high",
        "Storage account allows TLS below version 1.2",
        "TLS 1.0 and 1.1 have known weaknesses; TLS 1.2+ is required.",
        "Set minimum TLS version to 1.2 on the storage account.",
        {"op": "in", "path": "properties.minimumTlsVersion", "value": ["TLS1_0", "TLS1_1"]}),
    _existing_rule("REL-VM-999", "reliability",
        ["microsoft.compute/virtualmachines"], "advisor_mapped", "low",
        "Azure Advisor reliability recommendation for VM",
        "Advisor has detected a reliability configuration gap on the VM.",
        "Review and action the Advisor reliability recommendation.",
        None, "advisor-reliability-vm"),
]

ALL_RULES: list[dict] = EXISTING_RULES + NEW_RULES


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _get_pool(settings) -> asyncpg.Pool:
    return await asyncpg.create_pool(
        dsn=settings.dsn_primary,
        min_size=1,
        max_size=3,
        command_timeout=30,
    )


async def _upsert_rule(conn: asyncpg.Connection, rule_dict: dict) -> str:
    now = datetime.now(UTC)
    rule_id = rule_dict["rule_id"]
    await conn.execute(
        """
        INSERT INTO waf_rules (
            id, rule_id, pillar, resource_types, evaluation_type,
            condition_dsl, prompt_template_ref, severity,
            title, description, recommendation,
            is_active, version, created_at, updated_at
        ) VALUES (
            $1, $2, $3::pillar, $4, $5::evaluation_type,
            $6::jsonb, $7, $8::severity,
            $9, $10, $11,
            $12, $13, $14, $15
        )
        ON CONFLICT (rule_id) DO UPDATE SET
            pillar              = EXCLUDED.pillar,
            resource_types      = EXCLUDED.resource_types,
            evaluation_type     = EXCLUDED.evaluation_type,
            condition_dsl       = EXCLUDED.condition_dsl,
            prompt_template_ref = EXCLUDED.prompt_template_ref,
            severity            = EXCLUDED.severity,
            title               = EXCLUDED.title,
            description         = EXCLUDED.description,
            recommendation      = EXCLUDED.recommendation,
            is_active           = EXCLUDED.is_active,
            version             = waf_rules.version + 1,
            updated_at          = EXCLUDED.updated_at
        """,
        uuid.uuid4(),
        rule_id,
        rule_dict["pillar"],
        rule_dict["resource_types"],
        rule_dict["evaluation_type"],
        __import__("json").dumps(rule_dict["condition_dsl"]) if rule_dict.get("condition_dsl") else None,
        rule_dict.get("prompt_template_ref"),
        rule_dict["severity"],
        rule_dict["title"],
        rule_dict["description"],
        rule_dict["recommendation"],
        rule_dict["is_active"],
        rule_dict["version"],
        now,
        now,
    )
    return rule_id


async def seed(dry_run: bool = False, pillar_filter: str | None = None) -> None:
    settings = SeederSettings()
    rules = ALL_RULES
    if pillar_filter:
        rules = [r for r in rules if r["pillar"] == pillar_filter]

    print(f"[seed_rules] {'DRY RUN — ' if dry_run else ''}Seeding {len(rules)} rules...")

    if dry_run:
        for r in rules:
            print(f"  WOULD UPSERT  {r['rule_id']:30s}  pillar={r['pillar']}  eval={r['evaluation_type']}")
        print(f"[seed_rules] Dry run complete — no database writes.")
        return

    pool = await _get_pool(settings)
    try:
        async with pool.acquire() as conn:
            seeded = 0
            for rule_dict in rules:
                rule_id = await _upsert_rule(conn, rule_dict)
                print(f"  UPSERTED  {rule_id}")
                seeded += 1
        print(f"[seed_rules] Done. {seeded} rules seeded.")
        print(f"\n  New controls covered (Phase 3):")
        for code in sorted(set(NEWLY_COVERED_CONTROLS)):
            print(f"    {code}")
        print(f"\n  Human-review-only (no ARM evidence):")
        for code in HUMAN_REVIEW_REQUIRED:
            print(f"    {code}  — requires human review")
    finally:
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed WAF rules into the database.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print rules that would be seeded without writing to the DB.")
    parser.add_argument("--pillar", default=None,
                        help="Only seed rules for a specific pillar (e.g. security).")
    args = parser.parse_args()

    try:
        asyncio.run(seed(dry_run=args.dry_run, pillar_filter=args.pillar))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[seed_rules] ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
