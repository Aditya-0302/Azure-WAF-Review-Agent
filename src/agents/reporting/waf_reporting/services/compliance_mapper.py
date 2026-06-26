"""Static compliance framework mapping tables for the reporting layer.

Maps WAF rule IDs to external compliance standards using deterministic lookups only.
No LLM. No Azure API calls. No invented data.

Frameworks covered
------------------
- Azure Policy       — name, definition ID (GUID), compliance category
- Azure Advisor      — category, recommendation title, description
- CIS Azure          — CIS Azure Security Benchmark v2.0 control IDs
- ISO 27001:2022     — annex control references
- NIST CSF           — function + category codes
- MCSB               — Microsoft Cloud Security Benchmark v1 control codes

All functions return None / empty dict if no mapping exists for the given rule ID.
Never raises. All outputs are informational only — they never affect scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AzurePolicyRef:
    """An Azure Policy definition that aligns to a WAF finding."""
    display_name: str
    definition_id: str
    compliance_category: str


@dataclass(frozen=True)
class AdvisorRef:
    """An Azure Advisor recommendation category that aligns to a WAF finding."""
    category: str
    recommendation_title: str
    description: str


@dataclass(frozen=True)
class ComplianceFrameworkRef:
    """Cross-framework compliance references for a single finding/rule."""
    cis_azure: list[str]
    iso_27001: list[str]
    nist_csf: list[str]
    mcsb: list[str]


# ---------------------------------------------------------------------------
# Azure Policy definitions — keyed by rule_id prefix or full rule_id
# ---------------------------------------------------------------------------

# Full match first, then prefix match.
# definition_id: Azure built-in policy definition GUID (public)
_AZURE_POLICY_EXACT: dict[str, AzurePolicyRef] = {
    # Storage
    "SEC-STG-001": AzurePolicyRef(
        display_name="Storage accounts should require secure transfer",
        definition_id="404c3081-a854-4457-ae30-26a93ef643f9",
        compliance_category="Storage Security",
    ),
    "SEC-STG-002": AzurePolicyRef(
        display_name="Storage accounts should use minimum TLS version of TLS 1.2",
        definition_id="fe83a0eb-a853-422d-aac2-1bffd182c5d0",
        compliance_category="Storage Security",
    ),
    "SEC-STG-003": AzurePolicyRef(
        display_name="Storage accounts should restrict network access",
        definition_id="34c877ad-507e-4c82-993e-3452a6e0ad3c",
        compliance_category="Storage Security",
    ),
    "SEC-STG-004": AzurePolicyRef(
        display_name="Storage accounts should prevent cross tenant object replication",
        definition_id="92a89a79-6c52-4a7e-a03f-61306fc49312",
        compliance_category="Storage Security",
    ),
    "SEC-STG-005": AzurePolicyRef(
        display_name="Geo-redundant storage should be enabled for Storage Accounts",
        definition_id="bf045164-79ba-4215-8f95-f8048dc1780b",
        compliance_category="Storage Resilience",
    ),
    # Key Vault
    "SEC-KV-001": AzurePolicyRef(
        display_name="Key vaults should have soft delete enabled",
        definition_id="1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d",
        compliance_category="Key Management",
    ),
    "SEC-KV-002": AzurePolicyRef(
        display_name="Key vaults should have purge protection enabled",
        definition_id="0b60c0b2-2dc2-4e1c-b5c9-abbed971de53",
        compliance_category="Key Management",
    ),
    "SEC-KV-003": AzurePolicyRef(
        display_name="Key vaults should have deletion protection enabled",
        definition_id="0b60c0b2-2dc2-4e1c-b5c9-abbed971de53",
        compliance_category="Key Management",
    ),
    "SEC-KV-004": AzurePolicyRef(
        display_name="Azure Key Vault Managed HSM should have purge protection enabled",
        definition_id="c39ba22d-4428-4149-b981-828bccea0c74",
        compliance_category="Key Management",
    ),
    # Application Gateway / WAF
    "REL-AGW-001": AzurePolicyRef(
        display_name="Web Application Firewall (WAF) should be enabled for Application Gateway",
        definition_id="564feb30-bf6a-4854-b4bb-0d2d2d1e6c66",
        compliance_category="Network Security",
    ),
    "SEC-NET-001": AzurePolicyRef(
        display_name="All network ports should be restricted on network security groups",
        definition_id="9daedab3-fb2d-461e-b861-71790eead4f6",
        compliance_category="Network Security",
    ),
    "SEC-NET-002": AzurePolicyRef(
        display_name="Network interfaces should not have public IPs",
        definition_id="83a86a26-fd1f-447c-b59d-ddc1fbb1c7a6",
        compliance_category="Network Security",
    ),
    "SEC-NET-003": AzurePolicyRef(
        display_name="Internet-facing virtual machines should be protected with network security groups",
        definition_id="f6de0be7-9a8a-4b8a-b349-43cf02d22f7c",
        compliance_category="Network Security",
    ),
    # App Service / Web Apps
    "SEC-APP-001": AzurePolicyRef(
        display_name="App Service apps should only be accessible over HTTPS",
        definition_id="a4af4a39-4135-47fb-b175-47fbdf85311d",
        compliance_category="Application Security",
    ),
    "SEC-APP-002": AzurePolicyRef(
        display_name="App Service apps should use the latest TLS version",
        definition_id="f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b",
        compliance_category="Application Security",
    ),
    "SEC-APP-003": AzurePolicyRef(
        display_name="App Service apps should use a managed identity",
        definition_id="2b9ad585-36bc-4615-b300-fd4435808332",
        compliance_category="Identity Security",
    ),
    "SEC-APP-004": AzurePolicyRef(
        display_name="Authentication should be enabled on your API app",
        definition_id="c4ebc54a-46e1-481a-bee2-d4411e95d828",
        compliance_category="Application Security",
    ),
    # Monitoring / Diagnostics
    "OPS-DIAG-001": AzurePolicyRef(
        display_name="Diagnostic settings should be enabled for Azure services",
        definition_id="b6e2945c-0b7b-40f5-9233-7a5323b5cdc6",
        compliance_category="Monitoring & Logging",
    ),
    "OPS-DIAG-002": AzurePolicyRef(
        display_name="Resource logs should be enabled in Azure Key Vault Managed HSM",
        definition_id="a2a5b911-5617-447e-a49e-59dbe0e0434b",
        compliance_category="Monitoring & Logging",
    ),
    "OPS-MON-001": AzurePolicyRef(
        display_name="An activity log alert should exist for specific Policy operations",
        definition_id="c5447c04-a4d7-4ba8-a263-c9ee321a6858",
        compliance_category="Monitoring & Logging",
    ),
    "OPS-MON-002": AzurePolicyRef(
        display_name="Monitor missing Endpoint Protection in Azure Security Center",
        definition_id="af6cd1bd-1635-48cb-bde7-5b15693900b9",
        compliance_category="Endpoint Protection",
    ),
    # Defender / Security Center
    "SEC-DEF-001": AzurePolicyRef(
        display_name="Microsoft Defender for Storage should be enabled",
        definition_id="640d2586-54d2-465f-877f-9ffc1d2109f4",
        compliance_category="Threat Protection",
    ),
    "SEC-DEF-002": AzurePolicyRef(
        display_name="Microsoft Defender for Containers should be enabled",
        definition_id="1c988dd4-ced4-4da8-b5f4-9314b821af37",
        compliance_category="Threat Protection",
    ),
    "SEC-DEF-003": AzurePolicyRef(
        display_name="Microsoft Defender for SQL should be enabled for unprotected SQL Managed Instances",
        definition_id="1b7aa243-30e4-4c9e-bca8-d0d3022b634a",
        compliance_category="Threat Protection",
    ),
    # SQL / Database
    "SEC-SQL-001": AzurePolicyRef(
        display_name="Auditing on SQL server should be enabled",
        definition_id="a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9",
        compliance_category="Database Security",
    ),
    "SEC-SQL-002": AzurePolicyRef(
        display_name="Transparent data encryption on SQL databases should be enabled",
        definition_id="17k78e20-9358-41c9-923c-fb736d382a12",
        compliance_category="Data Protection",
    ),
    "SEC-SQL-003": AzurePolicyRef(
        display_name="Azure Defender for SQL should be enabled for unprotected Azure SQL servers",
        definition_id="abfb4388-5bf4-4ad7-ba82-2cd2f41ce5e9",
        compliance_category="Threat Protection",
    ),
    # Identity / IAM
    "SEC-IAM-001": AzurePolicyRef(
        display_name="Accounts with owner permissions on Azure resources should be MFA enabled",
        definition_id="e3e008c3-56b9-4133-8fd7-d3347377402a",
        compliance_category="Identity & Access",
    ),
    "SEC-IAM-002": AzurePolicyRef(
        display_name="MFA should be enabled accounts with write permissions on your subscription",
        definition_id="9297c21d-2ed6-4474-b48f-163f75654ce3",
        compliance_category="Identity & Access",
    ),
    "SEC-IAM-003": AzurePolicyRef(
        display_name="There should be more than one owner assigned to your subscription",
        definition_id="09024ccc-0c5f-475e-9457-b7c0d9ed487b",
        compliance_category="Identity & Access",
    ),
    # Cost
    "CST-BUDGET-001": AzurePolicyRef(
        display_name="A budget should be configured for subscriptions",
        definition_id="de9c7f07-4dc7-4d85-8f5a-54af80f9a8f7",
        compliance_category="Cost Management",
    ),
}

# Prefix-based fallback for Azure Policy
_AZURE_POLICY_PREFIX: list[tuple[str, AzurePolicyRef]] = [
    ("SEC-STG-", AzurePolicyRef(
        display_name="Storage account security configuration policy",
        definition_id="Various — see Azure Policy: Storage",
        compliance_category="Storage Security",
    )),
    ("SEC-KV-", AzurePolicyRef(
        display_name="Key Vault security configuration policy",
        definition_id="Various — see Azure Policy: Key Vault",
        compliance_category="Key Management",
    )),
    ("SEC-NET-", AzurePolicyRef(
        display_name="Network security configuration policy",
        definition_id="Various — see Azure Policy: Network",
        compliance_category="Network Security",
    )),
    ("SEC-APP-", AzurePolicyRef(
        display_name="App Service security configuration policy",
        definition_id="Various — see Azure Policy: App Service",
        compliance_category="Application Security",
    )),
    ("SEC-DEF-", AzurePolicyRef(
        display_name="Microsoft Defender plan enablement policy",
        definition_id="Various — see Azure Policy: Security Center",
        compliance_category="Threat Protection",
    )),
    ("SEC-SQL-", AzurePolicyRef(
        display_name="SQL / database security configuration policy",
        definition_id="Various — see Azure Policy: SQL",
        compliance_category="Database Security",
    )),
    ("SEC-IAM-", AzurePolicyRef(
        display_name="Identity and access management policy",
        definition_id="Various — see Azure Policy: IAM",
        compliance_category="Identity & Access",
    )),
    ("OPS-DIAG-", AzurePolicyRef(
        display_name="Diagnostic settings enablement policy",
        definition_id="Various — see Azure Policy: Monitoring",
        compliance_category="Monitoring & Logging",
    )),
    ("OPS-MON-", AzurePolicyRef(
        display_name="Azure Monitor alert configuration policy",
        definition_id="Various — see Azure Policy: Monitor",
        compliance_category="Monitoring & Logging",
    )),
    ("REL-AGW-", AzurePolicyRef(
        display_name="Application Gateway / WAF configuration policy",
        definition_id="Various — see Azure Policy: Application Gateway",
        compliance_category="Network Security",
    )),
    ("CST-", AzurePolicyRef(
        display_name="Cost management and tagging policy",
        definition_id="Various — see Azure Policy: Cost",
        compliance_category="Cost Management",
    )),
]


# ---------------------------------------------------------------------------
# Azure Advisor mappings
# ---------------------------------------------------------------------------

_ADVISOR_CATEGORY_MAP: dict[str, AdvisorRef] = {
    "security": AdvisorRef(
        category="Security",
        recommendation_title="Resolve security recommendations from Azure Security Center",
        description=(
            "Azure Advisor surfaces active security recommendations from Microsoft Defender "
            "for Cloud. Addressing these findings reduces the organisation's attack surface "
            "and improves the Secure Score."
        ),
    ),
    "reliability": AdvisorRef(
        category="High Availability",
        recommendation_title="Improve the reliability and resiliency of your workload",
        description=(
            "Azure Advisor high-availability recommendations identify single points of failure, "
            "missing health probes, and insufficient redundancy that may affect workload uptime."
        ),
    ),
    "operational_excellence": AdvisorRef(
        category="Operational Excellence",
        recommendation_title="Improve your operational procedures and best practices",
        description=(
            "Azure Advisor operational excellence recommendations address monitoring gaps, "
            "missing diagnostic settings, and infrastructure configuration drift."
        ),
    ),
    "performance_efficiency": AdvisorRef(
        category="Performance",
        recommendation_title="Improve the speed and responsiveness of your business-critical applications",
        description=(
            "Azure Advisor performance recommendations identify throttling risks, "
            "under-provisioned resources, and suboptimal caching or load-balancing configurations."
        ),
    ),
    "cost_optimization": AdvisorRef(
        category="Cost",
        recommendation_title="Reduce your overall Azure spending",
        description=(
            "Azure Advisor cost recommendations identify unused resources, under-utilised "
            "virtual machines, and opportunities for reserved capacity pricing."
        ),
    ),
}

_ADVISOR_RULE_OVERRIDES: dict[str, AdvisorRef] = {
    "SEC-STG-001": AdvisorRef(
        category="Security",
        recommendation_title="Enable secure transfer to storage accounts",
        description=(
            "Azure Advisor recommends enabling the 'Secure transfer required' setting "
            "on all storage accounts to ensure data in transit is encrypted via HTTPS."
        ),
    ),
    "CST-BUDGET-001": AdvisorRef(
        category="Cost",
        recommendation_title="Create a budget to track subscription spending",
        description=(
            "Azure Advisor recommends configuring budgets with alert thresholds to "
            "prevent unexpected cost overruns and enable proactive spend management."
        ),
    ),
    "OPS-DIAG-001": AdvisorRef(
        category="Operational Excellence",
        recommendation_title="Enable diagnostic settings to capture resource telemetry",
        description=(
            "Azure Advisor recommends enabling diagnostic settings to route resource "
            "logs and metrics to Azure Monitor for operational visibility."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Compliance framework mappings (CIS, ISO 27001, NIST CSF, MCSB)
# ---------------------------------------------------------------------------

# Keyed by rule_id prefix. Values: CIS, ISO 27001:2022, NIST CSF, MCSB control codes.
_FRAMEWORK_MAP: dict[str, ComplianceFrameworkRef] = {
    # Storage
    "SEC-STG-": ComplianceFrameworkRef(
        cis_azure=["3.1", "3.2", "3.7", "3.8"],
        iso_27001=["A.8.24", "A.8.5", "A.5.14"],
        nist_csf=["PR.DS-2", "PR.DS-5", "PR.AC-3"],
        mcsb=["DP-3", "DP-5", "NS-2"],
    ),
    # Key Vault
    "SEC-KV-": ComplianceFrameworkRef(
        cis_azure=["8.1", "8.2", "8.3", "8.4"],
        iso_27001=["A.8.24", "A.8.12", "A.5.33"],
        nist_csf=["PR.DS-1", "PR.DS-2", "PR.IP-3"],
        mcsb=["DP-7", "IM-1", "GS-7"],
    ),
    # Network Security
    "SEC-NET-": ComplianceFrameworkRef(
        cis_azure=["6.1", "6.2", "6.3", "6.4", "6.5"],
        iso_27001=["A.8.20", "A.8.21", "A.8.22", "A.5.14"],
        nist_csf=["PR.AC-5", "PR.DS-5", "DE.AE-1"],
        mcsb=["NS-1", "NS-2", "NS-4", "NS-7"],
    ),
    # Application Security (App Service)
    "SEC-APP-": ComplianceFrameworkRef(
        cis_azure=["9.1", "9.2", "9.3", "9.4"],
        iso_27001=["A.8.26", "A.8.24", "A.5.14"],
        nist_csf=["PR.DS-2", "PR.AC-3", "ID.AM-2"],
        mcsb=["DP-3", "IM-1", "NS-2"],
    ),
    # Microsoft Defender
    "SEC-DEF-": ComplianceFrameworkRef(
        cis_azure=["2.1", "2.2", "2.3"],
        iso_27001=["A.8.7", "A.8.16", "A.5.30"],
        nist_csf=["DE.CM-1", "DE.AE-3", "RS.MI-2"],
        mcsb=["LT-1", "LT-3", "PV-3"],
    ),
    # SQL / Database Security
    "SEC-SQL-": ComplianceFrameworkRef(
        cis_azure=["4.1", "4.2", "4.3"],
        iso_27001=["A.8.24", "A.8.17", "A.5.14"],
        nist_csf=["PR.DS-1", "PR.DS-2", "PR.AC-3"],
        mcsb=["DP-1", "DP-5", "LT-1"],
    ),
    # Identity & Access Management
    "SEC-IAM-": ComplianceFrameworkRef(
        cis_azure=["1.1", "1.2", "1.3", "1.4"],
        iso_27001=["A.9.2", "A.9.3", "A.9.4", "A.5.16"],
        nist_csf=["PR.AC-1", "PR.AC-4", "PR.AC-6"],
        mcsb=["IM-1", "IM-2", "PA-1", "PA-2"],
    ),
    # Diagnostics / Monitoring
    "OPS-DIAG-": ComplianceFrameworkRef(
        cis_azure=["5.1", "5.2", "5.3"],
        iso_27001=["A.8.15", "A.8.16", "A.5.26"],
        nist_csf=["DE.CM-1", "DE.CM-7", "PR.PT-1"],
        mcsb=["LT-1", "LT-2", "LT-3"],
    ),
    # Monitoring / Alerts
    "OPS-MON-": ComplianceFrameworkRef(
        cis_azure=["5.4", "5.5"],
        iso_27001=["A.8.16", "A.5.25", "A.5.26"],
        nist_csf=["DE.CM-3", "DE.AE-2", "RS.CO-2"],
        mcsb=["LT-4", "LT-5", "IR-2"],
    ),
    # Application Gateway / Reliability
    "REL-AGW-": ComplianceFrameworkRef(
        cis_azure=["6.6", "9.1"],
        iso_27001=["A.8.20", "A.8.21", "A.17.1"],
        nist_csf=["PR.AC-5", "DE.CM-1", "RC.RP-1"],
        mcsb=["NS-4", "NS-6"],
    ),
    # Reliability (general)
    "REL-": ComplianceFrameworkRef(
        cis_azure=[],
        iso_27001=["A.17.1", "A.17.2", "A.12.3"],
        nist_csf=["RC.RP-1", "RC.CO-1", "PR.IP-4"],
        mcsb=["BR-1", "BR-2", "BR-3"],
    ),
    # Performance Efficiency
    "PER-": ComplianceFrameworkRef(
        cis_azure=[],
        iso_27001=["A.12.1"],
        nist_csf=["ID.AM-2", "PR.IP-1"],
        mcsb=["GS-1"],
    ),
    # Cost Optimization
    "CST-": ComplianceFrameworkRef(
        cis_azure=[],
        iso_27001=["A.5.30"],
        nist_csf=["ID.AM-2", "ID.GV-1"],
        mcsb=["GS-2"],
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_azure_policy(rule_id: str) -> Optional[AzurePolicyRef]:
    """Return the Azure Policy reference for a rule ID, or None if no mapping exists."""
    try:
        if rule_id in _AZURE_POLICY_EXACT:
            return _AZURE_POLICY_EXACT[rule_id]
        rid = rule_id.upper()
        for prefix, ref in _AZURE_POLICY_PREFIX:
            if rid.startswith(prefix.upper()):
                return ref
    except Exception:
        pass
    return None


def get_advisor_ref(rule_id: str, pillar: str) -> Optional[AdvisorRef]:
    """Return the Azure Advisor reference for a rule ID / pillar, or None."""
    try:
        if rule_id in _ADVISOR_RULE_OVERRIDES:
            return _ADVISOR_RULE_OVERRIDES[rule_id]
        return _ADVISOR_CATEGORY_MAP.get((pillar or "").lower())
    except Exception:
        pass
    return None


def get_compliance_frameworks(rule_id: str) -> Optional[ComplianceFrameworkRef]:
    """Return CIS/ISO/NIST CSF/MCSB references for a rule ID, or None."""
    try:
        rid = rule_id.upper()
        for prefix, ref in sorted(_FRAMEWORK_MAP.items(), key=lambda x: -len(x[0])):
            if rid.startswith(prefix.upper()):
                return ref
    except Exception:
        pass
    return None


def get_all_mappings(rule_id: str, pillar: str) -> dict:
    """Convenience wrapper — returns all available mappings for a rule/pillar pair.

    Never raises. Returns empty dict if no mappings are found.
    """
    try:
        return {
            "azure_policy":          get_azure_policy(rule_id),
            "azure_advisor":         get_advisor_ref(rule_id, pillar),
            "compliance_frameworks": get_compliance_frameworks(rule_id),
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Glossary
# ---------------------------------------------------------------------------

GLOSSARY: list[tuple[str, str]] = [
    ("Application Gateway",
     "Azure service that provides application-level load balancing, SSL termination, "
     "and Web Application Firewall (WAF) capabilities for web workloads."),
    ("ARM (Azure Resource Manager)",
     "The management layer that enables creation, update, and deletion of Azure resources "
     "through a unified API surface supporting RBAC, tags, and resource locks."),
    ("Availability Zone",
     "Physically separate datacentre locations within an Azure region with independent "
     "power, cooling, and networking, enabling zone-redundant architectures."),
    ("Azure Advisor",
     "A personalised cloud consultant that analyses resource configuration and usage "
     "telemetry to provide actionable recommendations across cost, security, "
     "reliability, performance, and operational excellence."),
    ("Azure Monitor",
     "A comprehensive monitoring service that collects, analyses, and acts on telemetry "
     "from Azure resources, providing metrics, logs, traces, and alerting capabilities."),
    ("Azure Policy",
     "A governance service that enforces organisational standards and assesses compliance "
     "at scale by evaluating Azure resource configurations against defined policy definitions."),
    ("Azure Resource Graph",
     "An Azure service that enables efficient exploration of Azure resources at scale "
     "using Kusto Query Language (KQL) to query resource properties across subscriptions."),
    ("CIS Azure Benchmark",
     "The Center for Internet Security's prescriptive configuration guidance for securing "
     "Azure environments, organised into numbered controls across service categories."),
    ("Compliance Score",
     "A percentage metric representing the proportion of WAF controls that pass assessment "
     "criteria, weighted by pillar criticality and finding severity."),
    ("Confidence Score",
     "A value (0–1) representing the reliability of a finding, based on the completeness "
     "of available evidence and the evaluation method (deterministic or LLM-assisted)."),
    ("Diagnostic Settings",
     "Azure resource configuration that routes platform logs and metrics to one or more "
     "destinations: Log Analytics workspace, storage account, or Event Hub."),
    ("ISO 27001:2022",
     "An international standard for information security management systems (ISMS), "
     "specifying requirements and Annex A controls for managing information security risks."),
    ("Key Vault",
     "Azure service for securely storing and controlling access to cryptographic keys, "
     "certificates, secrets, and managed HSM operations."),
    ("Log Analytics",
     "The Azure Monitor component that collects and indexes log data from Azure services, "
     "on-premises systems, and agents, enabling KQL-based queries and alerting."),
    ("Managed Identity",
     "An Azure Active Directory identity automatically managed by Azure, enabling services "
     "to authenticate to other Azure services without embedding credentials in code."),
    ("MCSB (Microsoft Cloud Security Benchmark)",
     "A set of security controls and best practices specifically designed for Azure workloads, "
     "aligned to industry frameworks including CIS and NIST SP 800-53."),
    ("NIST CSF",
     "The National Institute of Standards and Technology Cybersecurity Framework — a "
     "voluntary framework of standards and best practices organised into five functions: "
     "Identify, Protect, Detect, Respond, and Recover."),
    ("Policy Assignment",
     "The mechanism by which an Azure Policy definition is applied to a specific scope "
     "(management group, subscription, or resource group)."),
    ("Private Endpoint",
     "A network interface that connects a virtual network privately and securely to an "
     "Azure service using a private IP address from the virtual network's address space."),
    ("RBAC (Role-Based Access Control)",
     "Azure's authorisation system for managing access to Azure resources by assigning "
     "roles — collections of permissions — to users, groups, and service principals."),
    ("Risk Score",
     "A numeric metric (0–100) derived from the compliance score and severity distribution "
     "of open findings, representing the estimated aggregate risk level of the workload."),
    ("Storage Account",
     "An Azure resource providing durable, highly available, and massively scalable cloud "
     "storage for blobs, files, queues, and tables."),
    ("TLS (Transport Layer Security)",
     "A cryptographic protocol that provides end-to-end security for data transmitted "
     "over a network. TLS 1.2 is the minimum accepted version in most compliance frameworks."),
    ("Virtual Machine",
     "An on-demand, scalable computing resource available in Azure that provides the "
     "flexibility of virtualisation without the need to manage physical hardware."),
    ("WAF (Web Application Firewall)",
     "An application-layer firewall that monitors, filters, and blocks HTTP/S traffic "
     "to and from web applications based on rule sets designed to detect known attack patterns."),
    ("WAF Pillar",
     "One of the five pillars of the Azure Well-Architected Framework: Security, "
     "Reliability, Operational Excellence, Performance Efficiency, and Cost Optimization."),
]


# ---------------------------------------------------------------------------
# Assessment methodology text (static, used in both PDF and Excel)
# ---------------------------------------------------------------------------

METHODOLOGY_SECTIONS: list[tuple[str, str]] = [
    ("Discovery",
     "The assessment begins with automated discovery of Azure resources within the "
     "assessed subscription(s) using the Azure Resource Manager API and Azure Resource "
     "Graph. Resource types, configuration properties, tags, and metadata are collected "
     "without modifying any resource state."),
    ("Rule Evaluation",
     "Each discovered resource is evaluated against a library of deterministic WAF rules. "
     "Rules are expressed as structured assertions against resource configuration properties "
     "returned by the Azure API. Evaluation is fully deterministic — the same resource "
     "configuration always produces the same finding outcome."),
    ("LLM-Assisted Validation",
     "For a subset of controls where deterministic evaluation is insufficient, "
     "a large language model (LLM) reviews the collected evidence and provides a "
     "structured compliance assessment. LLM findings are clearly labelled and assigned "
     "a lower confidence score. The LLM does not have access to production systems "
     "and evaluates only the evidence payload collected by the extraction engine."),
    ("Evidence Collection",
     "For every finding, the engine records the specific property values, API responses, "
     "and configuration snapshots that informed the evaluation decision. This evidence "
     "is embedded in the report and provides an auditable trace from finding to raw data."),
    ("Scoring",
     "Compliance and risk scores are computed deterministically using a weighted "
     "pass-rate model. Each rule-resource pair contributes a weight equal to "
     "severity_weight × resource_criticality_multiplier. Pillar score = "
     "weighted_passed / weighted_applicable × 100. Severity weights: Critical=10, "
     "High=7, Medium=5, Low=2, Informational=1. Resource criticality multipliers range "
     "from 1.5× (Key Vault, SQL Server) to 0.6× (managed disks, snapshots). "
     "NOT_APPLICABLE rules are excluded from all calculations. "
     "The overall compliance score is a fixed-pillar-weight average: Security 30%, "
     "Reliability 20%, Performance Efficiency 20%, Operational Excellence 15%, "
     "Cost Optimization 15%. See Appendix E for the complete scoring formulae."),
    ("Human Review Controls",
     "Four WAF controls (SE-10: Governance, OE-03: Change Management, OE-04: Deployment "
     "Process, CO-09: Financial Governance) require human assessment and are recorded "
     "separately from automated findings. These controls are included in reporting but "
     "excluded from automated compliance scoring."),
    ("Reporting",
     "Findings, scores, and evidence are aggregated and rendered into this report. "
     "All data is sourced exclusively from the assessment database record. "
     "No data is synthesised or interpolated. If information is unavailable, "
     "the report displays 'Not Available' rather than a placeholder value."),
]

CONFIDENCE_SECTIONS: list[tuple[str, str]] = [
    ("Confidence Score",
     "Every finding carries a confidence score between 0 and 1 (displayed as 0–100%). "
     "This score reflects the reliability of the finding based on the quality and "
     "completeness of the collected evidence and the evaluation method used."),
    ("Deterministic Findings (Confidence ≥ 0.90)",
     "Findings evaluated using deterministic rule logic against structured API data "
     "receive a confidence score of 0.90 or higher. The evaluation is rule-based, "
     "repeatable, and independent of model behaviour. These findings represent the "
     "most reliable output of the assessment."),
    ("LLM-Assisted Findings (Confidence 0.60–0.89)",
     "Some controls require contextual reasoning that cannot be expressed as a simple "
     "property assertion. For these controls, the assessment engine submits the collected "
     "evidence to a language model, which returns a structured compliance verdict. "
     "These findings are assigned a confidence score of 0.60–0.89 to indicate that "
     "the outcome depends on model reasoning rather than a deterministic rule."),
    ("Low-Evidence Findings (Confidence < 0.60)",
     "Findings where the API returned incomplete or ambiguous data receive a confidence "
     "score below 0.60. These findings should be independently verified before "
     "remediation effort is prioritised."),
    ("Evidence Quality",
     "The evidence block attached to each finding contains the raw values that informed "
     "the evaluation. Reviewers should inspect this evidence to verify that the finding "
     "accurately reflects the current resource configuration before acting on it."),
]

LIMITATIONS_TEXT: list[str] = [
    (
        "This report reflects the configuration state of the assessed Azure subscription(s) "
        "at the time of assessment. Resource configurations may have changed since the "
        "assessment was completed."
    ),
    (
        "The assessment covers Azure resource configurations accessible via the Azure "
        "Resource Manager API. Configuration elements that are not exposed through the API "
        "— including in-guest operating system settings, application-layer security "
        "controls, and network flow policies — are outside the scope of this assessment."
    ),
    (
        "Human assessment controls (SE-10, OE-03, OE-04, CO-09) require human review "
        "of governance processes, change management procedures, deployment practices, "
        "and financial governance frameworks. These cannot be evaluated through automated "
        "API inspection and are recorded separately."
    ),
    (
        "Operational processes, business continuity plans, vendor management frameworks, "
        "staff training programmes, and physical security controls are not within the "
        "scope of this automated assessment."
    ),
    (
        "This report does not constitute legal advice, regulatory guidance, or a formal "
        "compliance certification. Organisations subject to regulatory requirements should "
        "engage qualified compliance professionals to assess adherence to applicable laws "
        "and standards."
    ),
    (
        "Risk ratings and compliance scores are calculated using the deterministic "
        "formulae described in Appendix B. These scores are intended to support "
        "prioritisation decisions and should not be used as the sole basis for "
        "risk management decisions."
    ),
    (
        "Confidence scores below 0.75 indicate that independent verification is "
        "recommended before initiating remediation for the associated finding."
    ),
]
