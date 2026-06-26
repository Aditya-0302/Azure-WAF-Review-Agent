"""New WAF rule definitions for Phase 3 + Phase 4 + Phase 5 + Phase 6 coverage expansion.

Each entry is a dict compatible with WafRule domain model (minus id / created_at /
updated_at, which are assigned at upsert time).  The seed script
``scripts/seed_rules.py`` loads this module and upserts every rule into the
``waf_rules`` table via WafRuleRepository.

Phase 3 — Covers 21 previously-uncovered WAF controls:
  Security   : SE-02, SE-06, SE-09
  Reliability: RE-04, RE-06, RE-09
  Oper. Exc. : OE-02, OE-08, OE-09, OE-10, OE-11
  Perf. Eff. : PE-01, PE-03, PE-04, PE-09, PE-12
  Cost Optim.: CO-01, CO-02, CO-04, CO-08, CO-12

Phase 4 — Reliability pillar expansion (10 additional deterministic rules):
  RE-02: REL-COSMOS-001, REL-AKS-001, REL-APP-004, REL-MYSQL-001,
         REL-POSTGRES-001, REL-REDIS-001, REL-AGW-003
  RE-03: REL-COSMOS-001
  RE-04: REL-LB-002
  RE-05: REL-LB-002
  RE-06: REL-EH-001
  RE-08: REL-STOR-004, REL-MYSQL-001, REL-POSTGRES-001

Phase 5 — Cost Optimization pillar expansion (12 additional deterministic rules):
  CO-05: CST-SCALE-001, CST-AKS-001
  CO-06: CST-APP-001, CST-PREM-001, CST-AGW-002, CST-GW-001,
         CST-SQL-002, CST-COSMOS-001
  CO-07: CST-STOR-003, CST-SNAP-001, CST-NIC-001, CST-LOG-001
  CO-10: CST-STOR-003, CST-LOG-001

Phase 6 — Operational Excellence pillar expansion (12 additional deterministic rules):
  OE-07: OPS-AKS-001, OPS-NSG-001, OPS-COSMOS-001, OPS-REDIS-001,
         OPS-ACT-001, OPS-SQL-003
  OE-08: OPS-COSMOS-001, OPS-STOR-001, OPS-REDIS-001, OPS-MYSQL-001,
         OPS-POSTGRES-001
  OE-09: OPS-APP-003
  OE-10: OPS-AKS-001, OPS-ACT-001, OPS-SQL-003
  OE-11: OPS-APP-003
  OE-12: OPS-AKS-002, OPS-VMSS-001

Human-review-only controls (no objective ARM evidence):
  SE-10, OE-03, OE-04, CO-09
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule(
    rule_id: str,
    pillar: str,
    resource_types: list[str],
    evaluation_type: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    condition_dsl: dict[str, Any] | None = None,
    prompt_template_ref: str | None = None,
) -> dict[str, Any]:
    """Return a rule definition dict ready for WafRuleRepository.upsert()."""
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


# ===========================================================================
# SECURITY RULES
# Covers: SE-02 (supply chain), SE-06 (app-to-platform boundary), SE-09 (vuln testing)
# ===========================================================================

# SE-02 / OE-02 — Container Registry content trust policy disabled
SEC_CR_001 = _rule(
    rule_id="SEC-CR-001",
    pillar="security",
    resource_types=["microsoft.containerregistry/registries"],
    evaluation_type="deterministic",
    severity="high",
    title="Container Registry content trust policy is disabled",
    description=(
        "Azure Container Registry (ACR) supports Docker Content Trust (DCT), which "
        "allows you to sign and verify image integrity. When content trust is disabled, "
        "unsigned or tampered images can be pulled and deployed, weakening supply-chain "
        "assurance. Enabling trust policy ensures only signed images are accepted."
    ),
    recommendation=(
        "Enable the trust policy on the container registry: "
        "az acr config content-trust update --name <registry> --resource-group <rg> "
        "--status enabled. Then enforce image signing in your CI/CD pipeline using "
        "Notation or Docker Content Trust (DOCKER_CONTENT_TRUST=1)."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.policies.trustPolicy"},
            {
                "op": "ne",
                "path": "properties.policies.trustPolicy.status",
                "value": "enabled",
            },
        ],
    },
)

# SE-02 / SE-09 — Microsoft Defender plan running on Free tier
# microsoft.security/pricings has one resource per Defender plan (Containers,
# VirtualMachines, SqlServers, etc.).  Any plan left on "Free" means Defender is
# not actively scanning that workload type.
SEC_DEF_001 = _rule(
    rule_id="SEC-DEF-001",
    pillar="security",
    resource_types=["microsoft.security/pricings"],
    evaluation_type="deterministic",
    severity="high",
    title="Microsoft Defender plan is on the Free tier — workload not actively scanned",
    description=(
        "Microsoft Defender for Cloud uses per-workload pricing plans "
        "(Containers, VirtualMachines, SqlServers, Storage, AppService, etc.). "
        "A plan on the 'Free' tier provides basic posture management only — no "
        "advanced threat detection, vulnerability assessment, or supply-chain "
        "scanning. Every production workload type should have the Standard plan "
        "enabled to satisfy SE-02 (software supply chain) and SE-09 (vulnerability testing)."
    ),
    recommendation=(
        "Enable the Defender Standard plan for this workload type: "
        "az security pricing create --name <PlanName> --tier Standard. "
        "Repeat for Containers, VirtualMachines, SqlServers, Storage, and AppService "
        "plan names in each subscription. Verify in: Defender for Cloud → Environment "
        "settings → Defender plans."
    ),
    condition_dsl={
        "op": "eq",
        "path": "properties.pricingTier",
        "value": "Free",
    },
)

# SE-06 — App Service not integrated with a VNet
SEC_NET_004 = _rule(
    rule_id="SEC-NET-004",
    pillar="security",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service has no VNet integration — traffic leaves the Microsoft backbone",
    description=(
        "Without VNet integration, outbound calls from an App Service traverse the "
        "public internet rather than a private virtual network. This violates SE-06 "
        "(application-to-platform responsibility boundary): the platform boundary "
        "should be enforced at the network layer so back-end services (databases, "
        "Key Vaults, APIs) are reachable only via private endpoints over a VNet."
    ),
    recommendation=(
        "Configure regional VNet Integration for the App Service: "
        "az webapp vnet-integration add --name <app> --resource-group <rg> "
        "--vnet <vnet-name> --subnet <subnet-name>. "
        "Also add private endpoints to back-end services (Azure SQL, Key Vault, "
        "Storage) so those resources are not reachable from the public internet."
    ),
    condition_dsl={
        "op": "is_null",
        "path": "properties.virtualNetworkSubnetId",
    },
)


# ===========================================================================
# RELIABILITY RULES
# Covers: RE-04 (graceful degradation), RE-06 (loose coupling), RE-09 (reliability testing)
# ===========================================================================

# RE-04 — Application Gateway has no custom health probes
REL_AGW_002 = _rule(
    rule_id="REL-AGW-002",
    pillar="reliability",
    resource_types=["microsoft.network/applicationgateways"],
    evaluation_type="deterministic",
    severity="medium",
    title="Application Gateway uses only default health probes — no custom probe configured",
    description=(
        "Azure Application Gateway health probes determine whether back-end instances "
        "are healthy before routing traffic to them. The default probe simply checks "
        "TCP connectivity on the backend port; it does not validate application-layer "
        "readiness. Without a custom HTTP probe on a meaningful endpoint (e.g., /health), "
        "the gateway may route requests to an instance that is TCP-alive but "
        "application-dead, causing user-facing errors. Custom probes are required for "
        "graceful degradation (RE-04)."
    ),
    recommendation=(
        "Add at least one custom health probe to the Application Gateway: "
        "az network application-gateway probe create --gateway-name <gw> "
        "--resource-group <rg> --name HealthProbe --protocol Http "
        "--host-name-from-http-settings true --path /health --interval 30 "
        "--timeout 30 --threshold 3. Then associate the probe with each "
        "HTTP setting via --probe."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.probes"},
            {"op": "length_eq", "path": "properties.probes", "value": 0},
        ],
    },
)

# RE-06 — Service Bus namespace on Basic tier (no dead-letter, no topics)
REL_SB_001 = _rule(
    rule_id="REL-SB-001",
    pillar="reliability",
    resource_types=["microsoft.servicebus/namespaces"],
    evaluation_type="deterministic",
    severity="medium",
    title="Service Bus namespace is on Basic tier — dead-letter queue and topics unavailable",
    description=(
        "The Basic Service Bus tier supports only queues with a 256 KB message size "
        "cap and no dead-letter queue (DLQ). Loose coupling (RE-06) requires the "
        "messaging infrastructure to be resilient: DLQs capture poison messages so "
        "processing continues uninterrupted, and the Standard/Premium tiers provide "
        "topics and subscriptions for fan-out patterns. A Basic-tier namespace limits "
        "architectural options and makes poison-message handling impossible."
    ),
    recommendation=(
        "Upgrade the Service Bus namespace to Standard or Premium tier: "
        "az servicebus namespace update --name <ns> --resource-group <rg> "
        "--sku Standard. For mission-critical workloads, use Premium with "
        "Availability Zones and geo-disaster recovery enabled."
    ),
    condition_dsl={
        "op": "eq",
        "path": "sku.name",
        "value": "Basic",
    },
)

# RE-09 — Recovery Services vault missing cross-region restore capability
REL_ASR_001 = _rule(
    rule_id="REL-ASR-001",
    pillar="reliability",
    resource_types=["microsoft.recoveryservices/vaults"],
    evaluation_type="deterministic",
    severity="high",
    title="Recovery Services vault does not have cross-region restore enabled",
    description=(
        "Azure Site Recovery and Azure Backup use Recovery Services vaults for "
        "disaster recovery (DR). Cross-region restore (CRR) allows recovery in a "
        "secondary region independent of a primary-region outage — a core requirement "
        "of RE-09 (test for reliability). When CRR is disabled, recovery workloads are "
        "constrained to the vault's primary region; a regional outage can block the "
        "recovery itself."
    ),
    recommendation=(
        "Enable cross-region restore on the Recovery Services vault: "
        "az backup vault backup-properties set --name <vault> --resource-group <rg> "
        "--cross-region-restore-flag true. Note: this requires GRS or RA-GRS "
        "redundancy. For Site Recovery scenarios, also run periodic failover tests "
        "('test failover') to satisfy RE-09 reliability testing requirements."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.redundancySettings"},
            {
                "op": "ne",
                "path": "properties.redundancySettings.crossRegionRestore",
                "value": "Enabled",
            },
        ],
    },
)


# ===========================================================================
# OPERATIONAL EXCELLENCE RULES
# Covers: OE-02 (supply-chain traceability via OPS-CR-001 maps to same SEC-CR-001
#         DSL), OE-08 (change management), OE-09 (automate deployments),
#         OE-10 (dashboards), OE-11 (safe deployments)
# Note: OE-02 coverage is achieved by mapping SEC-CR-001 to ["SE-02","OE-02"]
# in waf_control_mapping.json (one rule, two WAF codes).
# ===========================================================================

# OE-08 — VM lacks boot diagnostics (no audit/monitoring trail for change control)
OPS_DIAG_001 = _rule(
    rule_id="OPS-DIAG-001",
    pillar="operational_excellence",
    resource_types=["microsoft.compute/virtualmachines"],
    evaluation_type="deterministic",
    severity="low",
    title="Virtual machine boot diagnostics are disabled — operational visibility gap",
    description=(
        "Boot diagnostics capture the VM serial console log and a screenshot at each "
        "boot. This data is essential for diagnosing startup failures after patches, "
        "configuration changes, or deployments — a core part of OE-08 (change "
        "management). Without boot diagnostics, engineers have no visibility into why "
        "a VM failed to start after a change, severely extending mean-time-to-recover."
    ),
    recommendation=(
        "Enable boot diagnostics on the virtual machine: "
        "az vm boot-diagnostics enable --name <vm> --resource-group <rg>. "
        "For managed storage (recommended), omit --storage. "
        "After enabling, access logs via: "
        "az vm boot-diagnostics get-boot-log --name <vm> --resource-group <rg>."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.diagnosticsProfile"},
            {"op": "is_null", "path": "properties.diagnosticsProfile.bootDiagnostics"},
            {
                "op": "bool_eq",
                "path": "properties.diagnosticsProfile.bootDiagnostics.enabled",
                "value": False,
            },
        ],
    },
)

# OE-09 / OE-11 — App Service plan tier does not support deployment slots
OPS_SLOT_001 = _rule(
    rule_id="OPS-SLOT-001",
    pillar="operational_excellence",
    resource_types=["microsoft.web/serverfarms"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service plan is on a tier that does not support deployment slots",
    description=(
        "Deployment slots enable blue-green deployments and zero-downtime releases: "
        "a new version is deployed to a staging slot, validated, then swapped into "
        "production without any code change or restart in the production slot. This "
        "is the Azure-native pattern for OE-09 (automate build and deployment) and "
        "OE-11 (safely deploy workloads). Free, Shared, and Basic App Service plan "
        "tiers do not support deployment slots; Standard or higher is required."
    ),
    recommendation=(
        "Upgrade the App Service plan to Standard or higher: "
        "az appservice plan update --name <plan> --resource-group <rg> "
        "--sku S1. Then create a staging slot: "
        "az webapp deployment slot create --name <app> --resource-group <rg> "
        "--slot staging. Configure your CI/CD pipeline to deploy to staging and "
        "swap via az webapp deployment slot swap."
    ),
    condition_dsl={
        "op": "in",
        "path": "sku.tier",
        "value": ["Free", "Shared", "Basic", "Dynamic"],
    },
)

# OE-10 / PE-04 — App Service missing Application Insights instrumentation
OPS_MON_001 = _rule(
    rule_id="OPS-MON-001",
    pillar="operational_excellence",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service has no Application Insights connection string configured",
    description=(
        "Application Insights provides live metrics, distributed tracing, failure "
        "analysis, and performance profiling for web applications. Without it, "
        "operational dashboards (OE-10) have no application-layer telemetry and "
        "performance data collection (PE-04) is absent. The APPLICATIONINSIGHTS_"
        "CONNECTION_STRING (or legacy APPINSIGHTS_INSTRUMENTATIONKEY) app setting "
        "activates the SDK auto-instrumentation for .NET, Java, Node, and Python apps."
    ),
    recommendation=(
        "Create an Application Insights resource and link it to the App Service: "
        "az monitor app-insights component create --app <ai-name> "
        "--resource-group <rg> --location <loc> --kind web. "
        "Then set the connection string: "
        "az webapp config appsettings set --name <app> --resource-group <rg> "
        '--settings APPLICATIONINSIGHTS_CONNECTION_STRING="<conn-str>". '
        "Optionally enable auto-instrumentation via the App Service extension "
        "in Azure Portal → App Service → Application Insights blade."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.siteConfig.appSettings"},
            {
                "op": "not",
                "condition": {
                    "op": "any_match",
                    "path": "properties.siteConfig.appSettings",
                    "condition": {
                        "op": "in",
                        "path": "name",
                        "value": [
                            "APPLICATIONINSIGHTS_CONNECTION_STRING",
                            "APPINSIGHTS_INSTRUMENTATIONKEY",
                        ],
                    },
                },
            },
        ],
    },
)


# ===========================================================================
# PERFORMANCE EFFICIENCY RULES
# Covers: PE-01 (performance targets), PE-03 (service selection via Advisor),
#         PE-04 (collect data — via OPS-MON-001 mapping), PE-09 (bottlenecks via Advisor),
#         PE-12 (load testing via Advisor)
# ===========================================================================

# PE-01 — Metric alert rule has no action group (alert fires but nobody is notified)
PER_ALERT_001 = _rule(
    rule_id="PER-ALERT-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.insights/metricalerts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Metric alert rule has no action group — performance threshold breaches go unnoticed",
    description=(
        "Metric alert rules without action groups fire silently: the alert triggers "
        "in Azure Monitor but no notification (email, SMS, webhook, ITSM ticket) is "
        "sent. This defeats the purpose of defining performance targets (PE-01). "
        "Every production metric alert for CPU, memory, response time, request rate, "
        "or error rate must have at least one action group so the responsible team "
        "is notified when targets are breached."
    ),
    recommendation=(
        "Create an action group and attach it to the alert rule: "
        "az monitor action-group create --name <ag-name> --resource-group <rg> "
        "--action email admin admin@example.com. "
        "Then update the alert rule to reference the action group: "
        "az monitor metrics alert update --name <alert> --resource-group <rg> "
        "--action <action-group-id>. "
        "Verify all critical metric alert rules have at least one action group in "
        "Azure Portal → Monitor → Alerts → Alert rules."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.actions"},
            {"op": "length_eq", "path": "properties.actions", "value": 0},
        ],
    },
)

# PE-03 / PE-09 — Azure Advisor performance recommendation (advisor_mapped)
PER_ADV_001 = _rule(
    rule_id="PER-ADV-001",
    pillar="performance_efficiency",
    resource_types=["*"],
    evaluation_type="advisor_mapped",
    severity="medium",
    title="Azure Advisor performance recommendation — resource under-optimised for its workload",
    description=(
        "Azure Advisor continuously analyses telemetry across VMs, databases, "
        "App Services, and other resources to surface performance recommendations. "
        "Examples include: upgrade VM SKU for CPU-constrained workloads, switch to "
        "read replicas for read-heavy databases, enable CDN for static assets, or "
        "increase App Service plan cores. Open Advisor recommendations in the "
        "Performance category indicate that the right service or configuration has "
        "not yet been selected (PE-03) or that performance bottlenecks have been "
        "identified but not resolved (PE-09)."
    ),
    recommendation=(
        "Review and action open Azure Advisor Performance recommendations: "
        "az advisor recommendation list --category Performance. "
        "For each recommendation, evaluate the estimated impact and implement the "
        "suggested change. After remediation, dismiss the recommendation to keep "
        "the backlog clean."
    ),
    condition_dsl=None,
    prompt_template_ref="advisor-performance-general",
)

# PE-12 — Azure Advisor performance recommendation (also covers load-testing guidance)
PER_LT_001 = _rule(
    rule_id="PER-LT-001",
    pillar="performance_efficiency",
    resource_types=["*"],
    evaluation_type="advisor_mapped",
    severity="low",
    title="No evidence of load-testing configuration — peak-volume readiness unverified",
    description=(
        "PE-12 requires workloads to be load-tested at expected peak volumes before "
        "going live and after significant changes. Azure Load Testing (microsoft."
        "loadtestservice/loadtests) is the native service for this. Without load "
        "testing, capacity limits, latency regressions, and failure modes under "
        "concurrency remain unknown until production traffic exposes them. "
        "Azure Advisor surfaces scaling and capacity recommendations that serve as "
        "a proxy signal when no load testing resources are present."
    ),
    recommendation=(
        "Create an Azure Load Testing resource and run a baseline test: "
        "az load create --name <lt-name> --resource-group <rg> --location <loc>. "
        "Upload a JMeter or Locust test plan and run it targeting your staging "
        "environment. Integrate load testing into your CI/CD pipeline as a "
        "pre-production gate."
    ),
    condition_dsl=None,
    prompt_template_ref="advisor-performance-load-testing",
)


# ===========================================================================
# COST OPTIMIZATION RULES
# Covers: CO-01 (financial guardrails), CO-02 (cost tagging / alignment),
#         CO-04 (spending guardrails via budget alerts), CO-08 / CO-12 (Advisor cost)
# ===========================================================================

# CO-01 / CO-04 — Azure Budget has no notification thresholds configured
CST_BUDGET_001 = _rule(
    rule_id="CST-BUDGET-001",
    pillar="cost_optimization",
    resource_types=["microsoft.consumption/budgets"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Budget has no alert notification thresholds configured",
    description=(
        "Azure Budgets (microsoft.consumption/budgets) let teams define spend limits "
        "and alert when actual or forecasted spend crosses a threshold. A budget "
        "without notification thresholds (CO-01 financial guardrails, CO-04 spending "
        "guardrails) means overspend goes undetected until the invoice arrives. "
        "Every subscription should have at least one budget with alert thresholds "
        "at 80% actual and 100% forecast."
    ),
    recommendation=(
        "Add alert notifications to the budget: "
        "az consumption budget create --budget-name <name> --amount <amount> "
        "--time-grain Monthly --start-date <YYYY-MM-01> "
        "--end-date <YYYY-MM-01+12months> "
        "--contact-emails admin@example.com "
        "--threshold 80 --threshold-type Actual. "
        "Also add a forecast threshold at 100% to catch projected overruns. "
        "Review budgets in: Azure Portal → Cost Management → Budgets."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.notifications"},
            {"op": "length_eq", "path": "properties.notifications", "value": 0},
        ],
    },
)

# CO-02 — Resource is missing cost allocation tags
CST_COST_TAG_001 = _rule(
    rule_id="CST-COST-TAG-001",
    pillar="cost_optimization",
    resource_types=["*"],
    evaluation_type="deterministic",
    severity="low",
    title="Resource is missing a cost-centre or team tag — costs cannot be allocated by business unit",
    description=(
        "Cost allocation tags (e.g., CostCenter, cost-center, Team, Department) "
        "allow Azure Cost Management to break down spend by business unit, product "
        "team, or project. Without these tags, it is impossible to align actual "
        "Azure spend with business value (CO-02) or attribute costs to the correct "
        "budget owner. Every production resource should carry at minimum a "
        "CostCenter or Team tag."
    ),
    recommendation=(
        "Apply cost allocation tags to the resource: "
        "az tag update --resource-id <resource-id> --operation Merge "
        "--tags CostCenter=<code> Team=<team-name>. "
        "Enforce mandatory tagging at scale via Azure Policy "
        "(Require tag and its value), applied at the subscription or management "
        "group level. Track compliance in Azure Policy → Compliance dashboard."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "is_null", "path": "tags.CostCenter"},
            {"op": "is_null", "path": "tags.costcenter"},
            {"op": "is_null", "path": "tags.cost-center"},
            {"op": "is_null", "path": "tags.Cost-Center"},
            {"op": "is_null", "path": "tags.Team"},
            {"op": "is_null", "path": "tags.team"},
            {"op": "is_null", "path": "tags.Department"},
            {"op": "is_null", "path": "tags.department"},
        ],
    },
)

# CO-08 / CO-12 — Azure Advisor cost recommendation (advisor_mapped)
CST_ADV_001 = _rule(
    rule_id="CST-ADV-001",
    pillar="cost_optimization",
    resource_types=["*"],
    evaluation_type="advisor_mapped",
    severity="low",
    title="Azure Advisor cost recommendation — resource has actionable cost-saving opportunity",
    description=(
        "Azure Advisor analyses historical usage across VMs, disks, App Services, "
        "SQL databases, and other resources to surface cost-saving recommendations. "
        "Examples: shut down idle VMs, right-size over-provisioned resources, "
        "switch to reserved instances, tier cold blob data to Archive storage, "
        "or consolidate underutilised SQL elastic pools. Open Advisor cost "
        "recommendations indicate that environment costs are not optimised (CO-08) "
        "and that the Azure bill has not been reviewed and acted upon (CO-12)."
    ),
    recommendation=(
        "Review and action open Azure Advisor Cost recommendations: "
        "az advisor recommendation list --category Cost. "
        "Prioritise by estimated monthly savings. Implement each recommendation "
        "and dismiss it once applied. Schedule a monthly cost-review meeting "
        "using Azure Cost Management + Billing → Cost analysis."
    ),
    condition_dsl=None,
    prompt_template_ref="advisor-cost-general",
)


# ===========================================================================
# RELIABILITY RULES — Phase 4 expansion
# Covers: RE-02 (redundancy), RE-03 (cross-region continuity),
#         RE-04 (graceful degradation), RE-05 (observability),
#         RE-06 (loose coupling), RE-08 (backup and recovery)
# ===========================================================================

# RE-08 — Storage account blob versioning not enabled
REL_STOR_004 = _rule(
    rule_id="REL-STOR-004",
    pillar="reliability",
    resource_types=["microsoft.storage/storageaccounts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Storage account blob versioning is not enabled",
    description=(
        "Blob versioning automatically maintains prior versions of every object when "
        "it is overwritten or deleted. Without versioning, an accidental overwrite or "
        "application bug that corrupts data is permanent — there is no previous "
        "version to restore. Enabling versioning is essential for RE-08 "
        "(backup and recovery) because it provides a continuous change history "
        "independent of point-in-time restore windows."
    ),
    recommendation=(
        "Enable blob versioning on the storage account blob service: "
        "az storage account blob-service-properties update "
        "--account-name <sa> --resource-group <rg> --enable-versioning true. "
        "Note: versioning is not supported on accounts with hierarchical namespace "
        "(Azure Data Lake Storage Gen2) enabled. For ADLS Gen2, use soft delete "
        "and lifecycle management policies instead."
    ),
    condition_dsl={
        "op": "not",
        "condition": {
            "op": "bool_eq",
            "path": "properties.blobServiceProperties.isVersioningEnabled",
            "value": True,
        },
    },
)

# RE-04 / RE-05 — Load Balancer has no health probes configured
REL_LB_002 = _rule(
    rule_id="REL-LB-002",
    pillar="reliability",
    resource_types=["microsoft.network/loadbalancers"],
    evaluation_type="deterministic",
    severity="high",
    title="Load balancer has no health probes configured — backend health is unmonitored",
    description=(
        "Azure Load Balancer health probes continuously check whether backend "
        "instances are ready to serve traffic. Without a health probe, the load "
        "balancer cannot detect a failed or unresponsive backend and will continue "
        "routing requests to it, causing user-facing errors. Health probes are "
        "required for both graceful degradation (RE-04) and observability into "
        "backend reliability (RE-05). Every production load balancer must have at "
        "least one health probe targeting an application-layer endpoint."
    ),
    recommendation=(
        "Add a health probe to the load balancer: "
        "az network lb probe create --lb-name <lb> --resource-group <rg> "
        "--name HealthProbe --protocol Http --port 80 --path /health "
        "--interval 15 --threshold 2. "
        "Then associate the probe with each load balancing rule via --probe-name. "
        "Use HTTP or HTTPS probes targeting a meaningful application endpoint "
        "rather than a TCP-only probe, to detect application-layer failures."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.probes"},
            {"op": "length_eq", "path": "properties.probes", "value": 0},
        ],
    },
)

# RE-02 / RE-03 — Azure Cosmos DB account has only one region
REL_COSMOS_001 = _rule(
    rule_id="REL-COSMOS-001",
    pillar="reliability",
    resource_types=["microsoft.documentdb/databaseaccounts"],
    evaluation_type="deterministic",
    severity="high",
    title="Azure Cosmos DB account is deployed to a single region — no geo-redundancy",
    description=(
        "Azure Cosmos DB supports global distribution with automatic failover to "
        "secondary regions when the primary region becomes unavailable. A "
        "single-region deployment means a regional outage takes the database "
        "completely offline with no automatic recovery until the region recovers, "
        "violating RE-02 (redundancy) and RE-03 (cross-region business continuity). "
        "Mission-critical workloads require at least two regions with automatic "
        "failover enabled."
    ),
    recommendation=(
        "Add a secondary region to the Cosmos DB account: "
        "az cosmosdb update --name <account> --resource-group <rg> "
        "--locations regionName=<primary> failoverPriority=0 isZoneRedundant=true "
        "regionName=<secondary> failoverPriority=1 isZoneRedundant=true. "
        "Also enable automatic failover: "
        "az cosmosdb update --name <account> --resource-group <rg> "
        "--enable-automatic-failover true. "
        "For the highest availability, use zone-redundant deployments in each region."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.locations"},
            {"op": "length_lte", "path": "properties.locations", "value": 1},
        ],
    },
)

# RE-02 — AKS cluster node pools not spread across Availability Zones
REL_AKS_001 = _rule(
    rule_id="REL-AKS-001",
    pillar="reliability",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="high",
    title="AKS cluster has agent pool(s) not spread across Availability Zones",
    description=(
        "Azure Kubernetes Service (AKS) node pools can be spread across Availability "
        "Zones so that a datacenter-level failure removes only a subset of nodes, "
        "keeping the cluster operational. Without zone spreading (RE-02), all nodes "
        "of a pool reside in a single zone — a zone outage makes the affected "
        "workloads unschedulable until the zone recovers. Zone redundancy must be "
        "configured at cluster creation time and cannot be added to existing pools."
    ),
    recommendation=(
        "Create a new AKS cluster (or node pool) with zone spreading: "
        "az aks create --name <cluster> --resource-group <rg> "
        "--zones 1 2 3 --node-count 3. "
        "For an existing cluster, add a new zone-redundant node pool and migrate "
        "workloads: az aks nodepool add --cluster-name <cluster> "
        "--resource-group <rg> --name <pool> --zones 1 2 3 --node-count 3. "
        "Use the Cluster Autoscaler with a minimum of one node per zone."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.agentPoolProfiles"},
            {
                "op": "any_match",
                "path": "properties.agentPoolProfiles",
                "condition": {
                    "op": "or",
                    "conditions": [
                        {"op": "is_null", "path": "availabilityZones"},
                        {"op": "length_lte", "path": "availabilityZones", "value": 1},
                    ],
                },
            },
        ],
    },
)

# RE-02 — App Service plan zone redundancy not enabled
REL_APP_004 = _rule(
    rule_id="REL-APP-004",
    pillar="reliability",
    resource_types=["microsoft.web/serverfarms"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service plan zone redundancy is not enabled",
    description=(
        "App Service plan zone redundancy spreads instances across all Availability "
        "Zones in the region automatically. Without it, the platform places all "
        "instances in a single zone; a zone outage causes complete downtime even "
        "when the plan has multiple instances. Zone redundancy (RE-02) requires "
        "Premium v2 or v3 (PremiumV2, PremiumV3) tier or Isolated v2 and a minimum "
        "of three instances — it cannot be enabled on Free, Shared, or Basic plans."
    ),
    recommendation=(
        "Upgrade the App Service plan to PremiumV2/PremiumV3 and enable zone "
        "redundancy: az appservice plan update --name <plan> --resource-group <rg> "
        "--sku P1v3 --zone-redundant. "
        "Also set --number-of-workers 3 (minimum required for zone redundancy). "
        "Note: zone redundancy cannot be changed on an existing plan; a new plan "
        "must be created, apps migrated, and the old plan deleted."
    ),
    condition_dsl={
        "op": "not",
        "condition": {
            "op": "bool_eq",
            "path": "properties.zoneRedundant",
            "value": True,
        },
    },
)

# RE-06 — Event Hub namespace on Basic tier (no consumer groups, no geo-DR)
REL_EH_001 = _rule(
    rule_id="REL-EH-001",
    pillar="reliability",
    resource_types=["microsoft.eventhub/namespaces"],
    evaluation_type="deterministic",
    severity="medium",
    title="Event Hub namespace is on Basic tier — geo-disaster recovery and consumer groups unavailable",
    description=(
        "The Event Hub Basic tier restricts consumer groups to one per event hub, "
        "provides only 1-day event retention, and does not support the Geo-Disaster "
        "Recovery (Geo-DR) pairing feature. Geo-DR is required for RE-06 (reliable "
        "loose coupling) so that the messaging infrastructure can failover to a "
        "secondary namespace independently of the primary-region workload. "
        "Standard and Premium tiers provide Geo-DR pairing, 7-day retention, "
        "and up to 20 consumer groups per event hub."
    ),
    recommendation=(
        "Upgrade the Event Hub namespace to Standard or Premium tier: "
        "az eventhubs namespace update --name <ns> --resource-group <rg> "
        "--sku Standard. "
        "After upgrading, configure Geo-DR pairing: "
        "az eventhubs georecovery-alias create --alias <alias-name> "
        "--resource-group <rg> --namespace-name <primary-ns> "
        "--partner-namespace <secondary-ns-arm-id>. "
        "For the highest SLA, use Premium tier with Availability Zones enabled."
    ),
    condition_dsl={
        "op": "eq",
        "path": "sku.name",
        "value": "Basic",
    },
)

# RE-02 / RE-08 — Azure Database for MySQL Flexible Server not zone-redundant
REL_MYSQL_001 = _rule(
    rule_id="REL-MYSQL-001",
    pillar="reliability",
    resource_types=["microsoft.dbformysql/flexibleservers"],
    evaluation_type="deterministic",
    severity="high",
    title="Azure Database for MySQL Flexible Server high availability mode is not zone-redundant",
    description=(
        "Azure Database for MySQL Flexible Server offers Zone-Redundant High "
        "Availability (HA), which provisions a standby replica in a different "
        "Availability Zone with synchronous replication and automatic failover in "
        "under 60 seconds. Without Zone-Redundant HA, a zone outage takes the "
        "database offline until the zone recovers, directly violating RE-02 "
        "(redundancy) and RE-08 (backup and recovery). The default 'Disabled' HA "
        "mode provides no automatic failover capability for zone failures."
    ),
    recommendation=(
        "Enable Zone-Redundant High Availability on the MySQL Flexible Server: "
        "az mysql flexible-server update --name <server> --resource-group <rg> "
        "--high-availability ZoneRedundant. "
        "This requires a supported region and Business Critical or General Purpose "
        "compute tier. Also confirm that --standby-zone is set to a different zone "
        "than --zone to maximise datacenter-level isolation."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.highAvailability"},
            {
                "op": "ne",
                "path": "properties.highAvailability.mode",
                "value": "ZoneRedundant",
            },
        ],
    },
)

# RE-02 / RE-08 — Azure Database for PostgreSQL Flexible Server not zone-redundant
REL_POSTGRES_001 = _rule(
    rule_id="REL-POSTGRES-001",
    pillar="reliability",
    resource_types=["microsoft.dbforpostgresql/flexibleservers"],
    evaluation_type="deterministic",
    severity="high",
    title="Azure Database for PostgreSQL Flexible Server high availability mode is not zone-redundant",
    description=(
        "Azure Database for PostgreSQL Flexible Server Zone-Redundant High "
        "Availability provisions a standby server in a separate Availability Zone "
        "with synchronous replication. Automatic failover completes in under 120 "
        "seconds — the primary fails over to the standby transparently. Without "
        "Zone-Redundant HA, the database has no automatic failover for zone-level "
        "failures, undermining RE-02 (redundancy) and RE-08 (backup and recovery). "
        "The default 'Disabled' mode provides no zone protection."
    ),
    recommendation=(
        "Enable Zone-Redundant High Availability on the PostgreSQL Flexible Server: "
        "az postgres flexible-server update --name <server> --resource-group <rg> "
        "--high-availability ZoneRedundant. "
        "Note: HA mode can only be changed (enabled/disabled) on existing servers — "
        "the standby zone cannot be modified without recreation. "
        "Confirm the region supports Zone-Redundant HA before enabling."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.highAvailability"},
            {
                "op": "ne",
                "path": "properties.highAvailability.mode",
                "value": "ZoneRedundant",
            },
        ],
    },
)

# RE-02 — Azure Cache for Redis (Premium) not configured with Availability Zones
REL_REDIS_001 = _rule(
    rule_id="REL-REDIS-001",
    pillar="reliability",
    resource_types=["microsoft.cache/redis"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Cache for Redis Premium tier is not zone-redundant",
    description=(
        "Azure Cache for Redis Premium tier supports Availability Zone deployment, "
        "spreading cache nodes across multiple datacenters within a region. Without "
        "zone-redundant configuration, all cache nodes reside in a single zone — a "
        "zone outage makes the cache unavailable, potentially causing application "
        "failures or severe latency degradation that cascades to backend services. "
        "This rule applies only to Premium-tier caches; Basic and Standard tiers do "
        "not support Availability Zones and are not flagged (Not Applicable)."
    ),
    recommendation=(
        "Create a new Premium Redis cache with Availability Zones: "
        "az redis create --name <cache> --resource-group <rg> "
        "--location <region> --sku Premium --vm-size p1 "
        "--zones 1 2 3. "
        "Note: availability zones cannot be added to an existing Redis cache. "
        "A new cache must be created, data migrated (using SCAN + DUMP/RESTORE or "
        "geo-replication import), and the old cache decommissioned."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "sku.name", "value": "Premium"},
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "zones"},
                    {"op": "length_lte", "path": "zones", "value": 1},
                ],
            },
        ],
    },
)

# RE-02 — Application Gateway not deployed across Availability Zones
REL_AGW_003 = _rule(
    rule_id="REL-AGW-003",
    pillar="reliability",
    resource_types=["microsoft.network/applicationgateways"],
    evaluation_type="deterministic",
    severity="high",
    title="Application Gateway is not zone-redundant — single zone of failure for all ingress traffic",
    description=(
        "Azure Application Gateway v2 (Standard_v2, WAF_v2) supports Availability "
        "Zone deployment, distributing gateway instances across multiple datacenters. "
        "Without zone redundancy, all instances reside in a single zone — a zone "
        "failure takes all inbound traffic offline, making the Application Gateway a "
        "single point of failure for the entire workload (RE-02). Zone-redundant "
        "deployment is supported only on Standard_v2 and WAF_v2 SKUs; v1 SKUs "
        "(Standard, WAF) are deprecated and do not support zones."
    ),
    recommendation=(
        "Migrate to Application Gateway v2 with zone redundancy: "
        "az network application-gateway create --name <gw> --resource-group <rg> "
        "--sku WAF_v2 --capacity 2 --zones 1 2 3 "
        "--public-ip-address <pip-name> --vnet-name <vnet> --subnet <subnet>. "
        "For existing v2 gateways without zones, the gateway must be recreated with "
        "zones specified (zones are set at creation time). "
        "Ensure the associated public IP is also Standard SKU and zone-redundant."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "zones"},
            {"op": "length_eq", "path": "zones", "value": 0},
        ],
    },
)


# ===========================================================================
# COST OPTIMIZATION RULES — Phase 5 expansion
# Covers: CO-05 (dynamic allocation), CO-06 (rightsize assets),
#         CO-07 (optimize component costs), CO-10 (optimize workload costs)
# ===========================================================================

# CO-07 / CO-10 — StorageV2 account missing last-access-time tracking (prerequisite for auto-tiering)
CST_STOR_003 = _rule(
    rule_id="CST-STOR-003",
    pillar="cost_optimization",
    resource_types=["microsoft.storage/storageaccounts"],
    evaluation_type="deterministic",
    severity="low",
    title="StorageV2 account does not have last-access-time tracking enabled — automated blob tiering cannot be configured",
    description=(
        "Azure Blob Storage lifecycle management can automatically tier blobs from Hot "
        "to Cool to Archive based on last-access time. This requires Last Access Time "
        "Tracking to be enabled on the blob service. Without it, lifecycle policies can "
        "only tier by creation date (not actual usage), leading to premature or missed "
        "tiering and unnecessarily high storage costs (CO-07, CO-10). This rule applies "
        "only to General Purpose v2 (StorageV2) accounts; File-only and Premium accounts "
        "are not applicable."
    ),
    recommendation=(
        "Enable last-access-time tracking on the storage account: "
        "az storage account blob-service-properties update "
        "--account-name <sa> --resource-group <rg> "
        "--enable-last-access-tracking true. "
        "Then create a lifecycle management policy that transitions blobs accessed "
        "more than 30 days ago to Cool tier, and 90 days ago to Archive tier."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "kind", "value": "StorageV2"},
            {
                "op": "or",
                "conditions": [
                    {
                        "op": "is_null",
                        "path": "properties.blobServiceProperties.lastAccessTimeTrackingPolicy",
                    },
                    {
                        "op": "not",
                        "condition": {
                            "op": "bool_eq",
                            "path": "properties.blobServiceProperties.lastAccessTimeTrackingPolicy.enable",
                            "value": True,
                        },
                    },
                ],
            },
        ],
    },
)

# CO-06 — Premium App Service plan with only one instance (no HA, may be over-provisioned)
CST_APP_001 = _rule(
    rule_id="CST-APP-001",
    pillar="cost_optimization",
    resource_types=["microsoft.web/serverfarms"],
    evaluation_type="deterministic",
    severity="medium",
    title="Premium App Service plan has only one instance — paying for Premium SKU without high-availability benefit",
    description=(
        "A PremiumV2, PremiumV3, or Isolated App Service plan costs significantly more "
        "than Standard; the extra cost is justified when multiple instances provide "
        "high availability or zone-redundancy is enabled. A single-instance Premium plan "
        "provides no redundancy benefit over Standard tier and is likely over-provisioned "
        "(CO-06). Standard S1/S2/S3 plans support multi-instance HA at lower cost; "
        "PremiumV3 adds larger SKU sizes and zone redundancy when three or more "
        "instances are used."
    ),
    recommendation=(
        "Either downgrade to Standard tier if Premium-specific features are not required: "
        "az appservice plan update --name <plan> --resource-group <rg> --sku S1. "
        "Or increase the instance count to justify Premium tier and enable zone "
        "redundancy: az appservice plan update --name <plan> --resource-group <rg> "
        "--number-of-workers 3. "
        "Review CPU/memory requirements and traffic patterns before changing tiers."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "in",
                "path": "sku.tier",
                "value": ["PremiumV2", "PremiumV3", "Isolated", "IsolatedV2"],
            },
            {
                "op": "lte",
                "path": "sku.capacity",
                "value": 1,
            },
        ],
    },
)

# CO-07 — Managed disk snapshot is full (non-incremental) — costs same as the full disk
CST_SNAP_001 = _rule(
    rule_id="CST-SNAP-001",
    pillar="cost_optimization",
    resource_types=["microsoft.compute/snapshots"],
    evaluation_type="deterministic",
    severity="low",
    title="Managed disk snapshot is full (non-incremental) — stores an entire disk copy regardless of change rate",
    description=(
        "Azure Disk Snapshots can be full (non-incremental) or incremental. "
        "Full snapshots store a complete copy of the managed disk, regardless of how "
        "much data changed since the last snapshot. Incremental snapshots store only "
        "the blocks that changed since the previous snapshot, dramatically reducing "
        "storage consumption and cost (CO-07) for workloads with low change rates. "
        "For most workloads, incremental snapshots are the appropriate default and "
        "cost a fraction of full snapshots of the same disk."
    ),
    recommendation=(
        "Use incremental snapshots when creating new snapshots: "
        "az snapshot create --name <snap> --resource-group <rg> "
        "--source <disk-name> --incremental. "
        "For existing full snapshots, evaluate whether they can be replaced by "
        "incremental snapshots and delete the full copies after verification. "
        "Note: cross-region copy and certain export operations may still require "
        "full snapshots for specific scenarios."
    ),
    condition_dsl={
        "op": "not",
        "condition": {
            "op": "bool_eq",
            "path": "properties.incremental",
            "value": True,
        },
    },
)

# CO-07 — Network Interface not attached to any VM (orphaned)
CST_NIC_001 = _rule(
    rule_id="CST-NIC-001",
    pillar="cost_optimization",
    resource_types=["microsoft.network/networkinterfaces"],
    evaluation_type="deterministic",
    severity="low",
    title="Network interface is not attached to any virtual machine — orphaned resource consuming a private IP address",
    description=(
        "Azure Network Interface Cards (NICs) not attached to a virtual machine are "
        "orphaned resources. While a NIC itself has minimal direct cost, it occupies "
        "a private IP address in the subnet, can block decommissioning of related "
        "network resources, and contributes to configuration drift (CO-07). Orphaned "
        "NICs typically result from deleting a VM without removing its associated "
        "resources. Identifying and removing them improves cost hygiene and reduces "
        "network address space consumption."
    ),
    recommendation=(
        "Review and delete orphaned NICs: "
        "az network nic delete --name <nic> --resource-group <rg>. "
        "Before deleting, verify the NIC is truly unused by confirming no stopped "
        "VMs or Azure services reference it. "
        "Automate orphan detection using Azure Resource Graph: "
        'az graph query -q "Resources | where type == '
        "'microsoft.network/networkinterfaces' "
        'and isnull(properties.virtualMachine)".'
    ),
    condition_dsl={
        "op": "is_null",
        "path": "properties.virtualMachine",
    },
)

# CO-07 / CO-10 — Log Analytics workspace retention > 90 days (beyond included window)
CST_LOG_001 = _rule(
    rule_id="CST-LOG-001",
    pillar="cost_optimization",
    resource_types=["microsoft.operationalinsights/workspaces"],
    evaluation_type="deterministic",
    severity="medium",
    title="Log Analytics workspace data retention exceeds 90 days — additional per-GB retention charges apply",
    description=(
        "Azure Log Analytics charges for data retention beyond the included window. "
        "Retention from 30 to 90 days is typically included in ingestion pricing for "
        "most table types. Beyond 90 days, each GB-month of retained data incurs an "
        "additional charge (CO-07). Many workspaces retain data longer than compliance "
        "or operational requirements mandate. For long-term archival, exporting to "
        "Azure Storage (Cool or Archive tier) via data export rules is dramatically "
        "cheaper while still meeting compliance retention requirements (CO-10)."
    ),
    recommendation=(
        "Review and reduce interactive retention to the minimum compliant period: "
        "az monitor log-analytics workspace update --workspace-name <ws> "
        "--resource-group <rg> --retention-time 90. "
        "For data that must be kept beyond 90 days for compliance, configure "
        "long-term retention at archive pricing: "
        "az monitor log-analytics workspace table update --name <table> "
        "--workspace-name <ws> --resource-group <rg> --total-retention-time 365. "
        "Or export to a Storage account with lifecycle management to Archive tier."
    ),
    condition_dsl={
        "op": "gt",
        "path": "properties.retentionInDays",
        "value": 90,
    },
)

# CO-05 — App Service plan (Standard+) has autoscale disabled
CST_SCALE_001 = _rule(
    rule_id="CST-SCALE-001",
    pillar="cost_optimization",
    resource_types=["microsoft.web/serverfarms"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service plan autoscale is disabled — fixed capacity cannot flex to demand, causing over- or under-provisioning",
    description=(
        "Without autoscale, an App Service plan runs at a fixed instance count "
        "regardless of actual traffic. During peak traffic the plan may be "
        "under-provisioned (causing HTTP 503 errors); during off-peak hours it is "
        "over-provisioned (wasting money). Autoscale (CO-05: dynamically allocate "
        "resources) allows the plan to add instances under load and scale in when "
        "idle, matching cost to actual demand. Autoscale is available on Standard, "
        "PremiumV2, PremiumV3, and Isolated tiers; Free and Basic do not support it."
    ),
    recommendation=(
        "Enable autoscale on the App Service plan via Azure Monitor: "
        "az monitor autoscale create --resource-group <rg> "
        "--resource <plan-resource-id> --resource-type Microsoft.Web/serverfarms "
        "--name <autoscale-name> --min-count 1 --max-count 10 --count 2. "
        "Add a scale-out rule: "
        "az monitor autoscale rule create --autoscale-name <autoscale-name> "
        "--resource-group <rg> --scale out 1 "
        '--condition "CpuPercentage > 70 avg 5m". '
        "Add a scale-in rule (CPU < 30%) to reduce cost during off-peak hours."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "in",
                "path": "sku.tier",
                "value": ["Standard", "PremiumV2", "PremiumV3", "Isolated", "IsolatedV2"],
            },
            {
                "op": "not",
                "condition": {
                    "op": "bool_eq",
                    "path": "properties.autoScaleEnabled",
                    "value": True,
                },
            },
        ],
    },
)

# CO-06 — General Purpose v2 storage account on Premium tier (Standard usually suffices)
CST_PREM_001 = _rule(
    rule_id="CST-PREM-001",
    pillar="cost_optimization",
    resource_types=["microsoft.storage/storageaccounts"],
    evaluation_type="deterministic",
    severity="medium",
    title="General Purpose v2 storage account is on Premium tier — Standard tier is sufficient for most blob and table workloads",
    description=(
        "Azure Storage Premium tier provides high IOPS and low latency backed by SSDs "
        "at approximately 3–5x the cost of Standard tier. Premium is appropriate for "
        "latency-sensitive workloads, premium file shares (FileStorage kind), or "
        "premium block blobs (BlockBlobStorage kind). A General Purpose v2 (StorageV2) "
        "account on Premium tier is unusual — most blob, queue, and table workloads do "
        "not require Premium IOPS and are over-provisioned (CO-06). Standard_LRS, "
        "Standard_ZRS, or Standard_GRS provide adequate performance at much lower cost."
    ),
    recommendation=(
        "Evaluate whether Premium IOPS are genuinely required by the workload. "
        "If not, recreate the storage account on Standard tier: "
        "az storage account create --name <sa-new> --resource-group <rg> "
        "--sku Standard_LRS --kind StorageV2 --access-tier Hot. "
        "Migrate data using AzCopy: "
        "azcopy sync 'https://<old>.blob.core.windows.net' 'https://<new>.blob.core.windows.net'. "
        "For high-IOPS workloads, prefer Azure Managed Disks (Premium SSD) over "
        "Premium storage accounts."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "kind", "value": "StorageV2"},
            {"op": "eq", "path": "sku.tier", "value": "Premium"},
        ],
    },
)

# CO-05 — AKS cluster node pools have cluster autoscaler disabled
CST_AKS_001 = _rule(
    rule_id="CST-AKS-001",
    pillar="cost_optimization",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="medium",
    title="AKS cluster node pool(s) have cluster autoscaler disabled — nodes cannot flex to workload demand",
    description=(
        "The AKS Cluster Autoscaler automatically adjusts node pool size based on "
        "pending pod scheduling pressure and node utilization. Without it, the node "
        "pool runs at a fixed node count regardless of actual workload: idle nodes "
        "during off-peak hours waste compute cost, and insufficient nodes during "
        "peak hours cause pod scheduling failures and application timeouts (CO-05). "
        "The autoscaler enables cost-efficient, demand-responsive capacity management "
        "and is a best practice for any non-fixed-capacity Kubernetes workload."
    ),
    recommendation=(
        "Enable the cluster autoscaler on each user node pool: "
        "az aks nodepool update --cluster-name <cluster> --resource-group <rg> "
        "--name <nodepool> --enable-cluster-autoscaler "
        "--min-count 1 --max-count 10. "
        "Set min-count to the minimum required to run system workloads and "
        "max-count to the expected peak capacity. "
        "Monitor autoscaler activity in Azure Portal → AKS → Insights → Node count. "
        "Consider using Spot node pools for non-critical, interruptible workloads "
        "for additional cost savings."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.agentPoolProfiles"},
            {
                "op": "any_match",
                "path": "properties.agentPoolProfiles",
                "condition": {
                    "op": "not",
                    "condition": {
                        "op": "bool_eq",
                        "path": "enableAutoScaling",
                        "value": True,
                    },
                },
            },
        ],
    },
)

# CO-06 — Application Gateway v1 SKU (deprecated, no autoscale, higher per-unit cost)
CST_AGW_002 = _rule(
    rule_id="CST-AGW-002",
    pillar="cost_optimization",
    resource_types=["microsoft.network/applicationgateways"],
    evaluation_type="deterministic",
    severity="high",
    title="Application Gateway is using the deprecated v1 SKU (Standard/WAF) — retirement April 2027, no autoscale support",
    description=(
        "Azure Application Gateway v1 SKUs (Standard, WAF) are deprecated and will "
        "be retired on 28 April 2027. v1 requires manual capacity provisioning via "
        "a fixed instance count — over-provisioning wastes cost (CO-06) and "
        "under-provisioning causes latency or dropped connections. The v2 SKUs "
        "(Standard_v2, WAF_v2) support autoscaling (eliminating over-provisioning), "
        "zone redundancy, static VIPs, and have better price-performance per "
        "Capacity Unit. Migration to v2 is required before the retirement date."
    ),
    recommendation=(
        "Migrate to Application Gateway v2 (Standard_v2 or WAF_v2): "
        "az network application-gateway create --name <new-gw> --resource-group <rg> "
        "--sku WAF_v2 --capacity 2 --zones 1 2 3 "
        "--public-ip-address <pip> --vnet-name <vnet> --subnet <subnet>. "
        "Recreate HTTP settings, listeners, rules, and health probes on the v2 gateway. "
        "Test with a blue-green DNS cutover before decommissioning v1. "
        "Refer to the official migration guide: "
        "https://learn.microsoft.com/azure/application-gateway/migrate-v1-v2"
    ),
    condition_dsl={
        "op": "in",
        "path": "properties.sku.name",
        "value": ["Standard", "WAF"],
    },
)

# CO-06 — VPN Gateway Basic SKU (deprecated, no SLA, limited throughput)
CST_GW_001 = _rule(
    rule_id="CST-GW-001",
    pillar="cost_optimization",
    resource_types=["microsoft.network/virtualnetworkgateways"],
    evaluation_type="deterministic",
    severity="medium",
    title="VPN Gateway is using the deprecated Basic SKU — no SLA, limited to 10 tunnels and 100 Mbps",
    description=(
        "The VPN Gateway Basic SKU is deprecated and carries no Azure SLA. It "
        "supports only 10 site-to-site VPN tunnels, a maximum of 100 Mbps aggregate "
        "throughput, no BGP routing protocol, no active-active configuration, and no "
        "Availability Zone support. While it has the lowest listed price, the "
        "operational constraints often force workarounds that cost more in aggregate "
        "(CO-06). VpnGw1 through VpnGw5 (and AZ variants for zone redundancy) provide "
        "SLA-backed, scalable, BGP-capable options at reasonable incremental cost."
    ),
    recommendation=(
        "Upgrade the VPN Gateway to a supported SKU: "
        "az network vnet-gateway update --name <gw> --resource-group <rg> "
        "--sku VpnGw1 --vpn-type RouteBased. "
        "Note: upgrading from Basic requires deletion and recreation of the gateway "
        "along with reconfiguration of all connections. Plan for a maintenance window "
        "and pre-stage all connection credentials. "
        "For zone redundancy, use VpnGw1AZ through VpnGw5AZ SKUs."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "properties.gatewayType", "value": "Vpn"},
            {"op": "eq", "path": "sku.name", "value": "Basic"},
        ],
    },
)

# CO-06 — SQL Database on Premium/Business Critical tier without elastic pool
CST_SQL_002 = _rule(
    rule_id="CST-SQL-002",
    pillar="cost_optimization",
    resource_types=["microsoft.sql/servers/databases"],
    evaluation_type="deterministic",
    severity="medium",
    title="SQL Database is on Premium or Business Critical tier but not in an elastic pool — shared compute may reduce cost",
    description=(
        "Azure SQL Database Premium (DTU) and Business Critical (vCore) tiers are the "
        "highest-cost options for single databases. When multiple databases on the same "
        "server have variable, non-overlapping peak usage patterns, consolidating them "
        "into an elastic pool shares compute resources across all databases, reducing "
        "per-database cost significantly (CO-06). A standalone high-tier database not "
        "in a pool is often over-provisioned for its average utilization, particularly "
        "when peak periods are short. Elastic pools allocate eDTUs or vCores from a "
        "shared pool, with each database bursting up to the pool maximum."
    ),
    recommendation=(
        "Evaluate moving the database to an elastic pool: "
        "az sql elastic-pool create --name <pool> --server <server> "
        "--resource-group <rg> --edition Premium --capacity 125. "
        "Then add the database to the pool: "
        "az sql db update --name <db> --server <server> --resource-group <rg> "
        "--elastic-pool-name <pool>. "
        "Review actual DTU/vCore utilisation in Azure Portal → SQL Database → "
        "Compute + Storage → Metrics to confirm right-sizing before migrating."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "in",
                "path": "sku.tier",
                "value": ["Premium", "BusinessCritical"],
            },
            {
                "op": "is_null",
                "path": "properties.elasticPoolId",
            },
        ],
    },
)

# CO-06 — Cosmos DB multi-region writes enabled on single-region account
CST_COSMOS_001 = _rule(
    rule_id="CST-COSMOS-001",
    pillar="cost_optimization",
    resource_types=["microsoft.documentdb/databaseaccounts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Cosmos DB has multi-region writes enabled with only one region — write cost premium incurred without redundancy benefit",
    description=(
        "Azure Cosmos DB charges approximately 25% more for write operations when "
        "multi-region writes (active-active) is enabled, compared to single-write-region "
        "mode. Multi-region writes require at least two regions to provide any geographic "
        "redundancy or latency benefit. When enabled on a single-region account, the "
        "write cost premium is incurred with no resilience or low-latency write "
        "improvement (CO-06). Either add a secondary region to justify the cost, or "
        "disable multi-region writes to reduce write request unit charges."
    ),
    recommendation=(
        "Option 1 — Add a secondary region to justify multi-region write cost: "
        "az cosmosdb update --name <account> --resource-group <rg> "
        "--locations regionName=<primary> failoverPriority=0 "
        "regionName=<secondary> failoverPriority=1. "
        "Option 2 — Disable multi-region writes to reduce write operation cost: "
        "az cosmosdb update --name <account> --resource-group <rg> "
        "--enable-multiple-write-locations false. "
        "Review read/write latency and SLA requirements before changing write mode."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "bool_eq",
                "path": "properties.enableMultipleWriteLocations",
                "value": True,
            },
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "properties.locations"},
                    {"op": "length_lte", "path": "properties.locations", "value": 1},
                ],
            },
        ],
    },
)


# ===========================================================================
# OPERATIONAL EXCELLENCE RULES — Phase 6 expansion
# Covers: OE-07 (monitoring practices), OE-08 (change management / recovery),
#         OE-09 (deploy automation), OE-10 (dashboards), OE-11 (safe deploy),
#         OE-12 (patch / upgrade management)
# ===========================================================================

# OE-07 / OE-10 — AKS cluster Container Insights (OMS agent) not enabled
OPS_AKS_001 = _rule(
    rule_id="OPS-AKS-001",
    pillar="operational_excellence",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="medium",
    title="AKS cluster Container Insights (OMS agent) is not enabled — no live node/pod monitoring",
    description=(
        "Azure Monitor Container Insights (OMS agent add-on) continuously collects "
        "CPU, memory, disk, and network metrics from every node and pod in the AKS "
        "cluster and sends them to a Log Analytics workspace. Without it, operators "
        "have no live visibility into container workloads, making performance diagnosis, "
        "capacity planning, and alert-driven response impossible (OE-07, OE-10). "
        "Container Insights is the Azure-native monitoring solution for Kubernetes and "
        "is required for any AKS cluster running production workloads."
    ),
    recommendation=(
        "Enable Container Insights on the AKS cluster: "
        "az aks enable-addons --name <cluster> --resource-group <rg> "
        "--addons monitoring --workspace-resource-id <la-workspace-id>. "
        "If no Log Analytics workspace exists, omit --workspace-resource-id and "
        "Azure will create a default workspace. "
        "After enabling, access metrics in: Azure Portal → AKS cluster → Insights."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.addonProfiles.omsAgent"},
            {
                "op": "not",
                "condition": {
                    "op": "bool_eq",
                    "path": "properties.addonProfiles.omsAgent.enabled",
                    "value": True,
                },
            },
        ],
    },
)

# OE-12 — AKS cluster auto-upgrade channel is "none" or absent
OPS_AKS_002 = _rule(
    rule_id="OPS-AKS-002",
    pillar="operational_excellence",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="medium",
    title="AKS cluster auto-upgrade channel is not configured — Kubernetes version upgrades are manual",
    description=(
        "AKS clusters that are not enrolled in an auto-upgrade channel require "
        "manual Kubernetes version upgrades. Without automation, clusters drift "
        "further behind supported versions, accumulating security vulnerabilities "
        "and losing access to new features. Azure provides upgrade channels — "
        "patch, stable, rapid, node-image — that automatically apply safe version "
        "upgrades during configured maintenance windows (OE-12). A channel of 'none' "
        "or absent autoUpgradeProfile is the default and leaves upgrade responsibility "
        "entirely to the operator."
    ),
    recommendation=(
        "Enable an auto-upgrade channel on the AKS cluster: "
        "az aks update --name <cluster> --resource-group <rg> "
        "--auto-upgrade-channel patch. "
        "For production clusters, use 'patch' (patch version upgrades only) combined "
        "with a planned maintenance window: "
        "az aks maintenanceconfiguration add --name <cluster> --resource-group <rg> "
        "--config-name default --weekday Monday --start-hour 2. "
        "Channels: patch (safest), stable (minor+patch), rapid (latest), node-image (node OS only)."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.autoUpgradeProfile.upgradeChannel"},
            {
                "op": "eq",
                "path": "properties.autoUpgradeProfile.upgradeChannel",
                "value": "none",
            },
        ],
    },
)

# OE-07 — NSG with no flow logs configured (blind spot for network traffic analysis)
OPS_NSG_001 = _rule(
    rule_id="OPS-NSG-001",
    pillar="operational_excellence",
    resource_types=["microsoft.network/networksecuritygroups"],
    evaluation_type="deterministic",
    severity="low",
    title="Network Security Group has no flow logs configured — network traffic is not being recorded",
    description=(
        "NSG flow logs record all IP traffic flows allowed and denied by the NSG, "
        "including source/destination IP, port, protocol, and bytes transferred. "
        "Without flow logs, security incidents, lateral movement, and unusual traffic "
        "patterns cannot be detected or investigated after the fact (OE-07). Flow logs "
        "are stored in a Storage account and can be analysed in Azure Traffic Analytics "
        "for visual dashboards. NSGs protecting production subnets must always have "
        "flow logging enabled with Traffic Analytics."
    ),
    recommendation=(
        "Enable NSG flow logs via Network Watcher: "
        "az network watcher flow-log create --location <region> "
        "--name <flow-log-name> --nsg <nsg-id> "
        "--storage-account <sa-id> --enabled true --format JSON --log-version 2. "
        "Enable Traffic Analytics for enhanced dashboards: add "
        "--traffic-analytics --workspace <la-workspace-id> --interval 10. "
        "Retain flow logs for at least 90 days to support incident investigations."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.flowLogs"},
            {"op": "length_eq", "path": "properties.flowLogs", "value": 0},
        ],
    },
)

# OE-07 / OE-08 — Cosmos DB backup policy not in Continuous mode
OPS_COSMOS_001 = _rule(
    rule_id="OPS-COSMOS-001",
    pillar="operational_excellence",
    resource_types=["microsoft.documentdb/databaseaccounts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Cosmos DB is using Periodic backup mode — continuous backup enables point-in-time restore",
    description=(
        "Azure Cosmos DB offers two backup modes: Periodic (default) and Continuous. "
        "Periodic mode takes full backups every 1–24 hours with a retention window of "
        "2–720 hours; restores require opening a support ticket and can take hours. "
        "Continuous mode (30-day or 7-day tiers) enables self-service point-in-time "
        "restore to any second within the retention window without a support ticket — "
        "essential for recovering from accidental deletes or corrupted writes (OE-08). "
        "Continuous backup also enables Live Restore for disaster recovery (OE-07)."
    ),
    recommendation=(
        "Migrate to Continuous backup mode: "
        "az cosmosdb update --name <account> --resource-group <rg> "
        "--backup-policy-type Continuous. "
        "Note: migration from Periodic to Continuous is one-way and cannot be reversed. "
        "Continuous backup is available on accounts without analytical store and "
        "supports all API types (NoSQL, MongoDB, Cassandra, Gremlin, Table). "
        "Choose the 7-day tier for development and the 30-day tier for production."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.backupPolicy"},
            {
                "op": "not",
                "condition": {
                    "op": "eq",
                    "path": "properties.backupPolicy.type",
                    "value": "Continuous",
                },
            },
        ],
    },
)

# OE-08 — Storage account blob soft delete disabled (no recovery window for accidental deletions)
OPS_STOR_001 = _rule(
    rule_id="OPS-STOR-001",
    pillar="operational_excellence",
    resource_types=["microsoft.storage/storageaccounts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Storage account blob soft delete is disabled — deleted blobs are permanently lost immediately",
    description=(
        "Blob soft delete retains deleted blobs and blob versions for a configurable "
        "number of days (1–365), allowing recovery from accidental deletions, overwrites, "
        "or application bugs without needing a full backup restore. Without soft delete, "
        "a DELETE operation on a blob is immediately permanent and unrecoverable — "
        "violating OE-08 (change management safety nets). Soft delete is a zero-cost "
        "operational safety net that should always be enabled on production storage "
        "accounts alongside blob versioning."
    ),
    recommendation=(
        "Enable blob soft delete on the storage account: "
        "az storage account blob-service-properties update "
        "--account-name <sa> --resource-group <rg> "
        "--enable-delete-retention true --delete-retention-days 14. "
        "Also consider enabling container soft delete: "
        "az storage account blob-service-properties update "
        "--account-name <sa> --resource-group <rg> "
        "--enable-container-delete-retention true --container-delete-retention-days 7. "
        "Review soft-deleted blobs via: az storage blob list --account-name <sa> "
        "--container-name <container> --include d."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {
                "op": "is_null",
                "path": "properties.blobServiceProperties.deleteRetentionPolicy",
            },
            {
                "op": "not",
                "condition": {
                    "op": "bool_eq",
                    "path": "properties.blobServiceProperties.deleteRetentionPolicy.enabled",
                    "value": True,
                },
            },
        ],
    },
)

# OE-12 — VMSS automatic OS image upgrade not enabled
OPS_VMSS_001 = _rule(
    rule_id="OPS-VMSS-001",
    pillar="operational_excellence",
    resource_types=["microsoft.compute/virtualmachinescalesets"],
    evaluation_type="deterministic",
    severity="medium",
    title="Virtual Machine Scale Set automatic OS image upgrade is disabled — OS patches require manual rolling upgrades",
    description=(
        "VMSS Automatic OS Image Upgrade continuously monitors the gallery image or "
        "platform image for new OS versions and automatically applies rolling upgrades "
        "across the scale set instances without downtime. Without it, every OS patch "
        "cycle requires a manual upgrade operation — a process prone to being delayed "
        "or skipped, leaving scale set instances on outdated OS images with unpatched "
        "vulnerabilities (OE-12). Automatic upgrade is compatible with health extension "
        "or load balancer health probes for zero-downtime rolling updates."
    ),
    recommendation=(
        "Enable automatic OS image upgrade on the VMSS: "
        "az vmss update --name <vmss> --resource-group <rg> "
        "--set upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade=true. "
        "Also configure a health probe or application health extension so the VMSS "
        "can verify each instance is healthy after upgrade before proceeding: "
        "az vmss update --name <vmss> --resource-group <rg> "
        "--set upgradePolicy.automaticOSUpgradePolicy.disableAutomaticRollback=false. "
        "Review the upgrade status via: az vmss rolling-upgrade get-latest."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {
                "op": "is_null",
                "path": "properties.upgradePolicy.automaticOSUpgradePolicy",
            },
            {
                "op": "not",
                "condition": {
                    "op": "bool_eq",
                    "path": "properties.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade",
                    "value": True,
                },
            },
        ],
    },
)

# OE-07 / OE-08 — Premium Redis cache persistence (RDB backup) not enabled
OPS_REDIS_001 = _rule(
    rule_id="OPS-REDIS-001",
    pillar="operational_excellence",
    resource_types=["microsoft.cache/redis"],
    evaluation_type="deterministic",
    severity="medium",
    title="Premium Azure Cache for Redis has RDB persistence disabled — cache data is lost on restart",
    description=(
        "Azure Cache for Redis Premium tier supports RDB (Redis Database) persistence, "
        "which periodically snapshots the in-memory dataset to a linked Storage account. "
        "Without persistence, a cache restart (due to failover, maintenance, or failure) "
        "results in a completely cold cache — every key must be repopulated from the "
        "origin database, potentially overwhelming it and causing latency spikes or "
        "timeouts for connected applications (OE-07, OE-08). RDB persistence allows the "
        "cache to reload its last snapshot on restart, minimising the cold-start impact. "
        "This rule applies only to Premium-tier caches; Basic and Standard caches do not "
        "support persistence and are not applicable."
    ),
    recommendation=(
        "Enable RDB persistence on the Premium Redis cache: "
        "az redis update --name <cache> --resource-group <rg> "
        "--set redisConfiguration.rdb-backup-enabled=true "
        "redisConfiguration.rdb-backup-frequency=60 "
        "redisConfiguration.rdb-backup-max-snapshot-count=1. "
        "Persistence requires a Premium-tier cache linked to an Azure Storage account "
        "in the same region. Alternatively, enable AOF (Append Only File) persistence "
        "for more frequent durability at the cost of higher storage I/O."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "sku.name", "value": "Premium"},
            {
                "op": "not",
                "condition": {
                    "op": "bool_eq",
                    "path": "properties.redisConfiguration.rdb-backup-enabled",
                    "value": True,
                },
            },
        ],
    },
)

# OE-09 / OE-11 — App Service health check path not configured
OPS_APP_003 = _rule(
    rule_id="OPS-APP-003",
    pillar="operational_excellence",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service health check path is not configured — unhealthy instances are not automatically removed from load balancing",
    description=(
        "App Service Health Check continuously pings a configured HTTP endpoint on each "
        "instance. When an instance fails two consecutive checks, App Service removes "
        "it from the load balancer rotation and restarts it — providing self-healing "
        "without operator intervention. Without a health check path, App Service has no "
        "application-layer signal and will route requests to instances that are "
        "process-alive but application-dead, causing user-facing errors (OE-11). "
        "Health checks also make slot swap safer (OE-09): the swap completes only after "
        "the staging slot responds to health check pings."
    ),
    recommendation=(
        "Configure a health check path on the App Service: "
        "az webapp config set --name <app> --resource-group <rg> "
        '--generic-configurations \'{"healthCheckPath": "/health"}\'. '
        "Implement the /health endpoint to verify database connectivity, downstream "
        "service availability, and application readiness — not just an HTTP 200. "
        "Set an appropriate timeout and failure threshold in the App Service configuration. "
        "Monitor health check outcomes in Azure Portal → App Service → Health Check."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.siteConfig.healthCheckPath"},
            {
                "op": "eq",
                "path": "properties.siteConfig.healthCheckPath",
                "value": "",
            },
        ],
    },
)

# OE-08 — Azure Database for MySQL Flexible Server backup retention below 14 days
OPS_MYSQL_001 = _rule(
    rule_id="OPS-MYSQL-001",
    pillar="operational_excellence",
    resource_types=["microsoft.dbformysql/flexibleservers"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Database for MySQL Flexible Server backup retention is below 14 days — insufficient recovery window",
    description=(
        "Azure Database for MySQL Flexible Server retains automated backups for a "
        "configurable period (1–35 days). Backups enable point-in-time restore to any "
        "second within the retention window. A retention period below 14 days is "
        "operationally risky: silent data corruption or application bugs that go "
        "unnoticed for more than the retention window cannot be recovered without the "
        "oldest backup available (OE-08). Microsoft recommends a minimum of 14 days "
        "for production databases to provide a meaningful recovery envelope. "
        "The default retention is 7 days."
    ),
    recommendation=(
        "Increase the backup retention period to at least 14 days: "
        "az mysql flexible-server update --name <server> --resource-group <rg> "
        "--backup-retention 14. "
        "For compliance scenarios requiring longer retention, export backups to "
        "Azure Blob Storage with lifecycle policies. "
        "Verify the retention setting in: "
        "Azure Portal → Azure Database for MySQL → <server> → Backup and restore."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.backup.backupRetentionDays"},
            {
                "op": "lt",
                "path": "properties.backup.backupRetentionDays",
                "value": 14,
            },
        ],
    },
)

# OE-08 — Azure Database for PostgreSQL Flexible Server backup retention below 14 days
OPS_POSTGRES_001 = _rule(
    rule_id="OPS-POSTGRES-001",
    pillar="operational_excellence",
    resource_types=["microsoft.dbforpostgresql/flexibleservers"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Database for PostgreSQL Flexible Server backup retention is below 14 days — insufficient recovery window",
    description=(
        "Azure Database for PostgreSQL Flexible Server retains automated backups for "
        "1–35 days. Point-in-time restore is the primary recovery mechanism for "
        "accidental data loss, schema changes gone wrong, or application-level data "
        "corruption. A retention window below 14 days provides insufficient coverage "
        "for bugs or silent corruptions that are only discovered days after the fact "
        "(OE-08). Microsoft recommends a minimum of 14 days for production workloads. "
        "The default retention is 7 days."
    ),
    recommendation=(
        "Increase the backup retention period to at least 14 days: "
        "az postgres flexible-server update --name <server> --resource-group <rg> "
        "--backup-retention 14. "
        "For regulatory requirements beyond 35 days, use pg_dump scheduled exports "
        "to Azure Blob Storage with lifecycle management. "
        "Verify the current retention in: "
        "Azure Portal → Azure Database for PostgreSQL → <server> → Backup and restore."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.backup.backupRetentionDays"},
            {
                "op": "lt",
                "path": "properties.backup.backupRetentionDays",
                "value": 14,
            },
        ],
    },
)

# OE-07 / OE-10 — Activity Log Alert has no action group (alert fires silently)
OPS_ACT_001 = _rule(
    rule_id="OPS-ACT-001",
    pillar="operational_excellence",
    resource_types=["microsoft.insights/activitylogalerts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Activity Log Alert has no action group configured — subscription events trigger alerts that notify nobody",
    description=(
        "Activity Log Alerts monitor subscription-level events such as resource "
        "creation/deletion, role assignment changes, policy violations, and service "
        "health events. An Activity Log Alert without an action group fires internally "
        "in Azure Monitor but sends no notification (email, SMS, webhook, ITSM ticket) "
        "to anyone. This silently defeats the operational monitoring intent (OE-07, "
        "OE-10). Critical events — such as a resource group deletion, a Key Vault "
        "access policy change, or an unexpected role assignment — must alert the "
        "responsible team immediately."
    ),
    recommendation=(
        "Create an action group and attach it to the Activity Log Alert: "
        "az monitor action-group create --name <ag-name> --resource-group <rg> "
        "--action email ops-team ops@example.com. "
        "Update the activity log alert to reference the action group: "
        "az monitor activity-log alert action-group add "
        "--name <alert-name> --resource-group <rg> "
        "--action-group <action-group-id>. "
        "Review all Activity Log Alerts in: "
        "Azure Portal → Monitor → Alerts → Alert rules → filter by Signal type = Activity log."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.actions.actionGroups"},
            {
                "op": "length_eq",
                "path": "properties.actions.actionGroups",
                "value": 0,
            },
        ],
    },
)

# OE-07 / OE-10 — SQL Server auditing not enabled
OPS_SQL_003 = _rule(
    rule_id="OPS-SQL-003",
    pillar="operational_excellence",
    resource_types=["microsoft.sql/servers"],
    evaluation_type="deterministic",
    severity="medium",
    title="SQL Server auditing is not enabled — database access and query events are not logged",
    description=(
        "SQL Server Auditing records database events — logins, schema changes, data "
        "reads/writes, and stored procedure executions — to a Log Analytics workspace, "
        "Storage account, or Event Hub. Without auditing, there is no access log for "
        "incident investigation, compliance reporting, or anomaly detection in database "
        "usage (OE-07, OE-10). Auditing is required by most regulatory frameworks "
        "(SOC2, ISO 27001, PCI-DSS, HIPAA) and is the foundation of database "
        "observability. Defender for SQL (OPS-SQL-001) detects threats but does not "
        "replace auditing — they serve different purposes."
    ),
    recommendation=(
        "Enable server-level auditing on the SQL Server: "
        "az sql server audit-policy update --name <server> --resource-group <rg> "
        "--state Enabled --lats true --lawid <log-analytics-workspace-id>. "
        "For a Storage account destination: "
        "az sql server audit-policy update --name <server> --resource-group <rg> "
        "--state Enabled --storage-account <sa-name>. "
        "Server-level auditing applies to all databases on the server automatically. "
        "Retain audit logs for a minimum of 90 days for compliance purposes."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.auditingSettings"},
            {
                "op": "ne",
                "path": "properties.auditingSettings.state",
                "value": "Enabled",
            },
        ],
    },
)


# ===========================================================================
# PERFORMANCE EFFICIENCY RULES — Phase 7 expansion
# Covers: PE-05 (right service selection), PE-06 (application platform efficiency),
#         PE-08 (data performance), PE-10 (CDN / content delivery),
#         PE-11 (scalability), PE-07 (performance targets / bottlenecks)
# ===========================================================================

# PE-05 / PE-07 — VM OS disk is Standard HDD (spinning disk) — use SSD for all production VMs
PER_VM_004 = _rule(
    rule_id="PER-VM-004",
    pillar="performance_efficiency",
    resource_types=["microsoft.compute/virtualmachines"],
    evaluation_type="deterministic",
    severity="medium",
    title="Virtual machine OS disk is using Standard HDD (Standard_LRS) — SSD recommended for production workloads",
    description=(
        "Standard HDD (Standard_LRS) managed disks use spinning hard drives with "
        "higher latency (single-digit milliseconds vs. sub-millisecond for SSD) and "
        "lower IOPS limits. Using HDD for the OS disk of a production VM causes slower "
        "boot times, higher OS paging latency, and worse performance under any workload "
        "that touches the OS volume (logging, temp files, page file). Standard SSD "
        "(StandardSSD_LRS) provides consistent performance at modest additional cost and "
        "is the minimum recommended tier for production VM OS disks (PE-05, PE-07). "
        "Premium SSD (Premium_LRS) is required for latency-sensitive data-tier VMs."
    ),
    recommendation=(
        "Upgrade the OS disk to at least Standard SSD: "
        "az disk update --name <disk-name> --resource-group <rg> "
        "--sku StandardSSD_LRS. "
        "Note: the VM must be deallocated to change the disk SKU: "
        "az vm deallocate --name <vm> --resource-group <rg>. "
        "For databases, caches, or high-IOPS workloads, use Premium_LRS instead. "
        "Use Ultra Disk (UltraSSD_LRS) only when sub-millisecond latency is required."
    ),
    condition_dsl={
        "op": "eq",
        "path": "properties.storageProfile.osDisk.managedDisk.storageAccountType",
        "value": "Standard_LRS",
    },
)

# PE-05 — Managed disk is Standard HDD — all production disks should use SSD
PER_DISK_001 = _rule(
    rule_id="PER-DISK-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.compute/disks"],
    evaluation_type="deterministic",
    severity="medium",
    title="Managed disk is using Standard HDD (Standard_LRS) — SSD delivers significantly better performance",
    description=(
        "Azure managed disks come in four tiers: Standard HDD (Standard_LRS), "
        "Standard SSD (StandardSSD_LRS), Premium SSD (Premium_LRS), and Ultra Disk. "
        "Standard HDD disks have the highest latency (up to single-digit millisecond) "
        "and lowest IOPS/throughput caps of any managed disk tier. For any disk attached "
        "to a production workload — OS, data, or log — Standard HDD imposes a performance "
        "ceiling that limits application throughput (PE-05). Standard SSD costs only "
        "marginally more but delivers consistent IOPS, lower latency, and an SLA that "
        "HDD lacks. HDD is appropriate only for backup disks, development, or archival "
        "scenarios."
    ),
    recommendation=(
        "Upgrade the managed disk to Standard SSD or higher: "
        "az disk update --name <disk-name> --resource-group <rg> --sku StandardSSD_LRS. "
        "The VM must be stopped (deallocated) to change the disk SKU: "
        "az vm deallocate --name <vm> --resource-group <rg>. "
        "For SQL Server log files, application data, or Redis cache: use Premium_LRS. "
        "Review disk performance metrics in Azure Monitor → Disk IOPS / Disk Throughput "
        "to validate the upgrade meets workload requirements."
    ),
    condition_dsl={
        "op": "eq",
        "path": "sku.name",
        "value": "Standard_LRS",
    },
)

# PE-05 / PE-06 — App Service plan on Free or Shared tier — CPU/memory/time limits apply
PER_APP_004 = _rule(
    rule_id="PER-APP-004",
    pillar="performance_efficiency",
    resource_types=["microsoft.web/serverfarms"],
    evaluation_type="deterministic",
    severity="high",
    title="App Service plan is on Free or Shared tier — strict CPU minute quotas and memory limits make production use impractical",
    description=(
        "Free (F1) and Shared (D1) App Service plan tiers impose hard CPU minute quotas "
        "(60 minutes/day on Free; 240 minutes/day on Shared), a 1 GB memory ceiling, "
        "no custom domain SSL on Free, no auto-scaling, and shared infrastructure with "
        "other tenants. These constraints make both tiers unsuitable for any production "
        "workload with real user traffic. Applications on these tiers experience CPU "
        "throttling once the daily quota is exhausted, causing HTTP 503 responses "
        "until midnight UTC (PE-05, PE-06). Upgrade to Basic (B1) or higher for "
        "guaranteed compute and no daily CPU quotas."
    ),
    recommendation=(
        "Upgrade the App Service plan to at least Basic tier: "
        "az appservice plan update --name <plan> --resource-group <rg> --sku B1. "
        "For production workloads needing auto-scale and deployment slots, use "
        "Standard (S1) or PremiumV3 (P1v3). "
        "Review the plan tier comparison at: "
        "https://azure.microsoft.com/pricing/details/app-service/windows/"
    ),
    condition_dsl={
        "op": "in",
        "path": "sku.tier",
        "value": ["Free", "Shared"],
    },
)

# PE-06 — App Service AlwaysOn not enabled — cold starts degrade response time
PER_APP_005 = _rule(
    rule_id="PER-APP-005",
    pillar="performance_efficiency",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service AlwaysOn is disabled — idle site is unloaded after 20 minutes, causing cold-start latency",
    description=(
        "When AlwaysOn is disabled (the default), Azure App Service unloads the "
        "application worker process after approximately 20 minutes of inactivity to "
        "reclaim resources. The next incoming request triggers a cold start — spawning "
        "a new worker, loading the application runtime, and warming up caches — which "
        "can add hundreds of milliseconds to several seconds of latency for the first "
        "request (PE-06). Enabling AlwaysOn keeps the worker process continuously "
        "running so responses are consistently fast. AlwaysOn is available on Basic "
        "tier and above; it cannot be enabled on Free or Shared plans."
    ),
    recommendation=(
        "Enable AlwaysOn for the App Service: "
        "az webapp config set --name <app> --resource-group <rg> --always-on true. "
        "Alternatively, enable it in Azure Portal → App Service → Configuration → "
        "General settings → Always On. "
        "Note: Consumption-plan Function Apps cannot use AlwaysOn; use Premium or "
        "Dedicated plan for Function Apps that require consistent warm startup. "
        "Also consider configuring a health check ping endpoint to complement AlwaysOn."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.siteConfig.alwaysOn"},
            {
                "op": "bool_eq",
                "path": "properties.siteConfig.alwaysOn",
                "value": False,
            },
        ],
    },
)

# PE-08 — Azure SQL Database on Basic tier (5 DTU hard cap — unsuitable for production)
PER_SQL_002 = _rule(
    rule_id="PER-SQL-002",
    pillar="performance_efficiency",
    resource_types=["microsoft.sql/servers/databases"],
    evaluation_type="deterministic",
    severity="high",
    title="Azure SQL Database is on the Basic tier — 5 DTU limit and 2 GB max size make it development-only",
    description=(
        "The Azure SQL Database Basic tier provides only 5 DTUs (Database Transaction "
        "Units) and a maximum database size of 2 GB, with a single concurrent "
        "connection limit that is far below any production workload. Under even modest "
        "query pressure, the database hits its DTU ceiling and queries queue, causing "
        "application timeouts and degraded user experience (PE-08). Basic is priced "
        "and designed exclusively for development, testing, or rarely-used databases. "
        "Any database backing a production application should be on Standard (S0+), "
        "General Purpose (GP_Gen5_2+), or Business Critical tier."
    ),
    recommendation=(
        "Upgrade the database to at least Standard S1 (20 DTU) for low-traffic "
        "production use, or General Purpose vCore for scalable workloads: "
        "az sql db update --name <db> --server <server> --resource-group <rg> "
        "--edition Standard --service-objective S1. "
        "For vCore (recommended for new workloads): "
        "az sql db update --name <db> --server <server> --resource-group <rg> "
        "--edition GeneralPurpose --family Gen5 --capacity 2. "
        "Review DTU consumption in Azure Portal → SQL Database → Compute + Storage → "
        "Metrics (DTU percentage) before upgrading."
    ),
    condition_dsl={
        "op": "eq",
        "path": "sku.tier",
        "value": "Basic",
    },
)

# PE-11 — Premium Redis without clustering — single shard limits throughput and dataset size
PER_REDIS_001 = _rule(
    rule_id="PER-REDIS-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.cache/redis"],
    evaluation_type="deterministic",
    severity="medium",
    title="Premium Azure Cache for Redis has no clustering configured — single shard limits throughput and maximum dataset size",
    description=(
        "Azure Cache for Redis Premium tier supports Redis Cluster, which shards the "
        "dataset across multiple nodes. Without clustering, the cache is constrained to "
        "a single primary shard — meaning dataset size is bounded by the single node "
        "memory (up to 120 GB on P5), and all write operations must go through one "
        "primary. Enabling clustering (shardCount > 0) distributes data and parallelises "
        "operations across shards, increasing both capacity and write throughput linearly "
        "with shard count (PE-11). Clustering is available exclusively on Premium tier; "
        "Basic and Standard caches are not applicable."
    ),
    recommendation=(
        "Enable Redis clustering by setting the shard count: "
        "az redis update --name <cache> --resource-group <rg> "
        "--shard-count 3. "
        "Note: enabling or changing shard count on an existing cache restarts the cache "
        "and flushes all data. Plan the change during a maintenance window. "
        "For key space sharding, ensure your application uses the Redis Cluster client "
        "library or a compatible client (e.g., StackExchange.Redis with cluster mode). "
        "Start with shardCount=3 and scale up if CPU or memory utilisation exceeds 75%."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "sku.name", "value": "Premium"},
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "properties.shardCount"},
                    {"op": "eq", "path": "properties.shardCount", "value": 0},
                ],
            },
        ],
    },
)

# PE-05 — Load Balancer Basic SKU — limited throughput, no performance SLA, no zone support
PER_LB_001 = _rule(
    rule_id="PER-LB-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.network/loadbalancers"],
    evaluation_type="deterministic",
    severity="medium",
    title="Load Balancer is using Basic SKU — no SLA, limited rules, and no Availability Zone support",
    description=(
        "Azure Load Balancer Basic SKU provides no Service Level Agreement, supports "
        "only 300 load balancing rules (vs. 1500 for Standard), cannot be combined "
        "with Availability Zone–redundant deployments, and has no support for "
        "Standard-tier Public IP Addresses. Under high connection rates, the Basic SKU "
        "does not provide SNAT port allocation guarantees, leading to SNAT exhaustion "
        "and connection failures at scale (PE-05). Standard Load Balancer offers an "
        "SLA, cross-zone load balancing, Health Check status via Azure Monitor, and "
        "backend pool support for any Virtual Machine in the VNet (not just VMs in the "
        "same availability set)."
    ),
    recommendation=(
        "Upgrade to Standard SKU Load Balancer: "
        "az network lb update --name <lb> --resource-group <rg> --sku Standard. "
        "Note: migrating from Basic to Standard SKU requires: (1) upgrading associated "
        "Public IP addresses to Standard SKU, (2) reopening NSG rules (Standard LB is "
        "secure by default — no implicit inbound access). "
        "Use the migration script: az network lb migrate --name <lb> --resource-group <rg>. "
        "Review the migration guide: "
        "https://learn.microsoft.com/azure/load-balancer/load-balancer-basic-upgrade-guidance"
    ),
    condition_dsl={
        "op": "eq",
        "path": "sku.name",
        "value": "Basic",
    },
)

# PE-05 — Application Gateway v2 with no autoscale — fixed capacity over- or under-provisions
PER_AGW_001 = _rule(
    rule_id="PER-AGW-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.network/applicationgateways"],
    evaluation_type="deterministic",
    severity="medium",
    title="Application Gateway v2 has no autoscale configured — fixed capacity cannot flex to traffic demand",
    description=(
        "Application Gateway v2 (Standard_v2, WAF_v2) supports autoscaling: the gateway "
        "adds or removes Capacity Units (CUs) based on measured traffic load. Without "
        "autoscale configuration, the gateway runs at a fixed instance count — "
        "over-provisioned during quiet periods (wasting cost) and under-provisioned "
        "during spikes (causing latency or dropped connections) (PE-05). Autoscale "
        "with a defined minCapacity provides a warm baseline while allowing burst "
        "capacity up to maxCapacity, giving both cost efficiency and performance "
        "elasticity. This check applies only to v2 SKUs; v1 (Standard, WAF) does not "
        "support autoscale."
    ),
    recommendation=(
        "Configure autoscale on the Application Gateway v2: "
        "az network application-gateway update --name <gw> --resource-group <rg> "
        "--set autoscaleConfiguration.minCapacity=2 autoscaleConfiguration.maxCapacity=10. "
        "Set minCapacity to the number of CUs needed to handle baseline traffic without "
        "scale-up delay. Set maxCapacity to the budget ceiling. "
        "Monitor Capacity Unit utilisation in Azure Monitor to tune these values. "
        "For WAF_v2, also enable WAF bot protection to reduce backend load."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "in",
                "path": "properties.sku.name",
                "value": ["Standard_v2", "WAF_v2"],
            },
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "properties.autoscaleConfiguration"},
                    {"op": "is_null", "path": "properties.autoscaleConfiguration.minCapacity"},
                ],
            },
        ],
    },
)

# PE-10 — CDN endpoint with no custom caching delivery policy (using default cache behaviour only)
PER_CDN_002 = _rule(
    rule_id="PER-CDN-002",
    pillar="performance_efficiency",
    resource_types=["microsoft.cdn/profiles/endpoints"],
    evaluation_type="deterministic",
    severity="low",
    title="Azure CDN endpoint has no custom caching delivery policy — default caching may not reflect content requirements",
    description=(
        "Azure CDN endpoints have a default caching behaviour based on Cache-Control "
        "and Expires headers sent by the origin. Without custom delivery rules, the CDN "
        "cannot cache content that lacks explicit cache headers, rewrite URLs for "
        "cache efficiency, override TTLs for specific content types, or bypass the "
        "cache for dynamic content. Custom delivery policy rules (PE-10) allow precise "
        "control: cache images/fonts/JS/CSS with long TTLs, bypass the cache for API "
        "responses, and redirect HTTP to HTTPS — all improving cache hit ratio, "
        "reducing origin load, and improving perceived latency for end users."
    ),
    recommendation=(
        "Add a custom caching rule to the CDN endpoint delivery policy: "
        "az cdn endpoint rule add --name <endpoint> --profile-name <profile> "
        "--resource-group <rg> --rule-name CacheStatic --order 1 "
        "--action-name CacheExpiration --cache-behavior Override "
        "--cache-duration 7.00:00:00. "
        "Common rules: 7-day TTL for images/CSS/JS, bypass cache for /api/*, "
        "HTTPS redirect for all HTTP requests. "
        "Monitor cache hit ratio in Azure Portal → CDN endpoint → Metrics → "
        "Cache Hit Ratio (target >90% for static content)."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.deliveryPolicy"},
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "properties.deliveryPolicy.rules"},
                    {
                        "op": "length_eq",
                        "path": "properties.deliveryPolicy.rules",
                        "value": 0,
                    },
                ],
            },
        ],
    },
)

# PE-08 / PE-09 — SQL Database Premium/Business Critical with read scale-out disabled
PER_SQL_003 = _rule(
    rule_id="PER-SQL-003",
    pillar="performance_efficiency",
    resource_types=["microsoft.sql/servers/databases"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure SQL Database (Premium/Business Critical) has read scale-out disabled — reporting queries load the primary",
    description=(
        "Azure SQL Database Premium (DTU) and Business Critical (vCore) tiers include "
        "a built-in read-only replica at no additional cost. Read scale-out routes "
        "read-only connections (using ApplicationIntent=ReadOnly in the connection string) "
        "to the replica, offloading reporting, analytics, and read-heavy queries from "
        "the primary replica. Without read scale-out enabled, all queries — including "
        "heavy read operations — compete for the same compute resources on the primary, "
        "increasing latency for transactional workloads (PE-08, PE-09). Enabling read "
        "scale-out is zero-cost for these tiers and can dramatically improve throughput."
    ),
    recommendation=(
        "Enable read scale-out on the SQL Database: "
        "az sql db update --name <db> --server <server> --resource-group <rg> "
        "--read-scale Enabled. "
        "Update application connection strings to use the read replica for reporting: "
        "Server=<server>.database.windows.net;ApplicationIntent=ReadOnly. "
        "Monitor primary vs. replica load in Azure Portal → SQL Database → "
        "Query Performance Insight → Top Resource Consuming Queries."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "in",
                "path": "sku.tier",
                "value": ["Premium", "BusinessCritical"],
            },
            {
                "op": "ne",
                "path": "properties.readScale",
                "value": "Enabled",
            },
        ],
    },
)

# PE-08 — Cosmos DB using Strong or BoundedStaleness consistency — synchronous write penalty
PER_COSMOS_001 = _rule(
    rule_id="PER-COSMOS-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.documentdb/databaseaccounts"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Cosmos DB is using Strong or BoundedStaleness consistency — write latency is significantly higher than weaker levels",
    description=(
        "Azure Cosmos DB consistency levels directly impact write latency. Strong "
        "consistency requires all replicas across all regions to acknowledge every write "
        "before the write is confirmed — adding cross-region synchronous round-trip time "
        "to every write. BoundedStaleness requires a quorum of replicas and also "
        "impacts throughput. In contrast, Session (the default), ConsistentPrefix, and "
        "Eventual consistency allow writes to return as soon as the local replica "
        "commits, with much lower latency. Most application patterns can use Session "
        "consistency (per-session read-your-writes guarantee) with no observable "
        "consistency degradation while dramatically improving write performance (PE-08)."
    ),
    recommendation=(
        "Downgrade the default consistency level to Session unless Strong or "
        "BoundedStaleness is a hard business requirement: "
        "az cosmosdb update --name <account> --resource-group <rg> "
        "--default-consistency-level Session. "
        "Session consistency guarantees read-your-writes within a session, satisfying "
        "most application requirements. Evaluate the impact with the Cosmos DB "
        "Consistency Explorer in the Azure Portal. "
        "If Strong consistency is required for regulatory compliance, consider if "
        "the data model can be restructured to isolate strongly consistent operations "
        "to a separate container or account."
    ),
    condition_dsl={
        "op": "in",
        "path": "properties.consistencyPolicy.defaultConsistencyLevel",
        "value": ["Strong", "BoundedStaleness"],
    },
)

# PE-05 — AKS system node pool using B-series (burstable) VM — limited sustained CPU
PER_AKS_001 = _rule(
    rule_id="PER-AKS-001",
    pillar="performance_efficiency",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="medium",
    title="AKS system node pool is using a B-series (burstable) VM SKU — sustained CPU is capped below baseline",
    description=(
        "Azure B-series (Burstable) VMs accumulate CPU credits during idle periods and "
        "spend credits during CPU-intensive workloads. When credits are exhausted, CPU "
        "performance drops to the baseline percentage — as low as 10–20% for B2s. "
        "AKS system node pools run critical Kubernetes system components (CoreDNS, "
        "metrics-server, kube-proxy, cert-manager, etc.) that must maintain consistent "
        "latency for all pod scheduling and DNS resolution. Running system components "
        "on burstable nodes risks CPU throttling under sustained load, causing pod "
        "scheduling delays, DNS timeouts, and cluster instability (PE-05). User node "
        "pools for dev/test workloads may use B-series; system pools should not."
    ),
    recommendation=(
        "Change the system node pool VM size to a non-burstable D-series or E-series: "
        "az aks nodepool add --cluster-name <cluster> --resource-group <rg> "
        "--name systempool2 --node-count 3 --node-vm-size Standard_D4s_v3 "
        "--mode System. "
        "Then cordon and drain the old system pool and delete it: "
        "az aks nodepool update --cluster-name <cluster> --resource-group <rg> "
        "--name <old-system-pool> --mode User. "
        "az aks nodepool delete --cluster-name <cluster> --resource-group <rg> "
        "--name <old-system-pool>. "
        "Minimum recommended system pool: Standard_D4s_v3 (4 vCPU, 16 GB RAM), 3 nodes."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "exists", "path": "properties.agentPoolProfiles"},
            {
                "op": "any_match",
                "path": "properties.agentPoolProfiles",
                "condition": {
                    "op": "and",
                    "conditions": [
                        {"op": "eq", "path": "mode", "value": "System"},
                        {
                            "op": "starts_with",
                            "path": "vmSize",
                            "value": "Standard_B",
                            "ci": True,
                        },
                    ],
                },
            },
        ],
    },
)


# ===========================================================================
# Phase 8 — Cross-pillar resource coverage expansion (26 new rules)
# New resource types: microsoft.keyvault/vaults, microsoft.network/virtualnetworks,
#   microsoft.network/azurefirewalls, microsoft.app/containerapps,
#   microsoft.compute/availabilitysets, microsoft.sql/managedinstances,
#   microsoft.eventgrid/topics, microsoft.insights/components,
#   microsoft.insights/actiongroups
# Expanded coverage: microsoft.web/sites, microsoft.compute/virtualmachines,
#   microsoft.containerservice/managedclusters
# ===========================================================================

# ---------------------------------------------------------------------------
# Security — Key Vault
# ---------------------------------------------------------------------------

# SE-01 / SE-02 — Key Vault RBAC authorization not enabled (uses access policies)
SEC_KV_006 = _rule(
    rule_id="SEC-KV-006",
    pillar="security",
    resource_types=["microsoft.keyvault/vaults"],
    evaluation_type="deterministic",
    severity="high",
    title="Key Vault is not using Azure RBAC authorization",
    description=(
        "When Azure Key Vault uses access policies instead of Azure RBAC, permission "
        "assignments are vault-scoped only and cannot be governed centrally via Azure "
        "Policy or audited through Azure Monitor RBAC logs. RBAC authorization provides "
        "fine-grained control at the individual secret/key/certificate level and integrates "
        "with Privileged Identity Management (PIM) for just-in-time access."
    ),
    recommendation=(
        "Enable Azure RBAC authorization: az keyvault update --name <vault> "
        "--enable-rbac-authorization true. Then assign built-in roles (Key Vault Secrets "
        "User, Key Vault Reader) to identities instead of access policies."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.enableRbacAuthorization"},
            {"op": "eq", "path": "properties.enableRbacAuthorization", "value": False},
        ],
    },
)

# SE-06 — Key Vault network access not restricted
SEC_KV_007 = _rule(
    rule_id="SEC-KV-007",
    pillar="security",
    resource_types=["microsoft.keyvault/vaults"],
    evaluation_type="deterministic",
    severity="medium",
    title="Key Vault network access is not restricted to specific networks",
    description=(
        "By default, Key Vault allows connections from all public networks. Unrestricted "
        "network access exposes secrets, keys, and certificates to any internet-based "
        "attacker that obtains or guesses valid credentials. Restricting access to known "
        "VNets and trusted Azure services dramatically reduces the attack surface."
    ),
    recommendation=(
        "Configure network ACLs with defaultAction Deny and add specific VNet rules and "
        "IP ranges: az keyvault update --default-action Deny --add network-acls virtualNetworkRules "
        "<subnet-id>. Consider also deploying a private endpoint."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.networkAcls"},
            {"op": "eq", "path": "properties.networkAcls.defaultAction", "value": "Allow"},
        ],
    },
)

# RE-06 — Key Vault purge protection not enabled
REL_KV_001 = _rule(
    rule_id="REL-KV-001",
    pillar="reliability",
    resource_types=["microsoft.keyvault/vaults"],
    evaluation_type="deterministic",
    severity="medium",
    title="Key Vault purge protection is not enabled",
    description=(
        "Without purge protection, a deleted Key Vault and its contents can be permanently "
        "and irrecoverably destroyed during the soft-delete retention period by any "
        "authorized principal. Purge protection prevents this, ensuring that deleted "
        "vaults remain recoverable for the full retention period (7–90 days)."
    ),
    recommendation=(
        "Enable purge protection: az keyvault update --name <vault> "
        "--enable-purge-protection true. Note: this cannot be disabled once enabled."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.enablePurgeProtection"},
            {"op": "eq", "path": "properties.enablePurgeProtection", "value": False},
        ],
    },
)

# ---------------------------------------------------------------------------
# Reliability & OE — Virtual Network
# ---------------------------------------------------------------------------

# RE-04 / RE-05 — VNet has no DDoS protection plan
REL_VNET_001 = _rule(
    rule_id="REL-VNET-001",
    pillar="reliability",
    resource_types=["microsoft.network/virtualnetworks"],
    evaluation_type="deterministic",
    severity="medium",
    title="Virtual Network has no Azure DDoS Protection plan attached",
    description=(
        "Azure DDoS Protection Standard provides enhanced DDoS mitigation tuned to the "
        "specific resources in the VNet. Without it, resources rely only on Azure "
        "platform-level DDoS basic protection, which may not stop volumetric or "
        "protocol attacks targeting your public endpoints."
    ),
    recommendation=(
        "Create or attach an Azure DDoS Protection Standard plan: "
        "az network ddos-protection create and then link it to the VNet via "
        "--ddos-protection-plan <plan-id>. Note the plan incurs a fixed monthly cost."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.ddosProtectionPlan"},
            {"op": "is_null", "path": "properties.ddosProtectionPlan.id"},
        ],
    },
)

# OE-07 — VNet uses Azure-provided DNS (no custom DNS servers)
OPS_VNET_001 = _rule(
    rule_id="OPS-VNET-001",
    pillar="operational_excellence",
    resource_types=["microsoft.network/virtualnetworks"],
    evaluation_type="deterministic",
    severity="low",
    title="Virtual Network uses Azure-provided DNS with no custom DNS servers configured",
    description=(
        "VNets relying solely on Azure-provided DNS cannot resolve private hybrid DNS "
        "zones, on-premises domains, or custom split-horizon namespaces. Specifying "
        "custom DNS servers (e.g., Azure Private DNS Resolver or domain controllers) "
        "enables consistent name resolution across hybrid environments."
    ),
    recommendation=(
        "Configure custom DNS server addresses on the VNet: "
        "az network vnet update --dns-servers <ip1> <ip2>. "
        "Use Azure Private DNS Resolver or domain controller IPs for hybrid scenarios."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.dhcpOptions"},
            {"op": "is_null", "path": "properties.dhcpOptions.dnsServers"},
            {"op": "length_eq", "path": "properties.dhcpOptions.dnsServers", "value": 0},
        ],
    },
)

# ---------------------------------------------------------------------------
# Security & Reliability — Azure Firewall
# ---------------------------------------------------------------------------

# SE-09 — Threat intelligence mode is Off
SEC_AFW_001 = _rule(
    rule_id="SEC-AFW-001",
    pillar="security",
    resource_types=["microsoft.network/azurefirewalls"],
    evaluation_type="deterministic",
    severity="high",
    title="Azure Firewall threat intelligence mode is Off",
    description=(
        "Azure Firewall integrates with Microsoft Defender threat intelligence to "
        "alert on or deny traffic to/from known malicious IP addresses and FQDNs. "
        "When threat intelligence mode is Off, this protection layer is disabled, "
        "allowing command-and-control traffic and connections to known malicious "
        "destinations to pass undetected."
    ),
    recommendation=(
        "Set threat intelligence mode to Alert or Deny: "
        "az network firewall update --threat-intel-mode Deny --name <fw> --resource-group <rg>. "
        "Start with Alert to baseline traffic, then switch to Deny after review."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.threatIntelMode"},
            {"op": "eq", "path": "properties.threatIntelMode", "value": "Off"},
        ],
    },
)

# RE-04 — Azure Firewall not deployed across Availability Zones
REL_AFW_001 = _rule(
    rule_id="REL-AFW-001",
    pillar="reliability",
    resource_types=["microsoft.network/azurefirewalls"],
    evaluation_type="deterministic",
    severity="medium",
    title="Azure Firewall is not deployed across Availability Zones",
    description=(
        "Deploying Azure Firewall without Availability Zones concentrates the instance "
        "in a single datacenter within a region. An AZ outage would make the firewall "
        "unavailable, disrupting all east-west and north-south traffic it inspects. "
        "Zone-redundant deployment ensures continued operation during AZ failures."
    ),
    recommendation=(
        "Redeploy the Azure Firewall with zone coverage: specify --zones 1 2 3 during "
        "az network firewall create. Note: changing zones requires recreation of the resource."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "zones"},
            {"op": "length_eq", "path": "zones", "value": 0},
        ],
    },
)

# ---------------------------------------------------------------------------
# Security, Reliability & OE — Container Apps
# ---------------------------------------------------------------------------

# SE-07 — Container App ingress allows insecure HTTP
SEC_CA_001 = _rule(
    rule_id="SEC-CA-001",
    pillar="security",
    resource_types=["microsoft.app/containerapps"],
    evaluation_type="deterministic",
    severity="medium",
    title="Container App ingress allows insecure HTTP traffic",
    description=(
        "When allowInsecure is enabled on Container App ingress, HTTP requests are "
        "forwarded to the application alongside HTTPS traffic. This allows credentials, "
        "session tokens, and sensitive data to be transmitted in plaintext and potentially "
        "intercepted by a network observer."
    ),
    recommendation=(
        "Disable insecure ingress on the Container App. In Bicep/ARM, set "
        "properties.configuration.ingress.allowInsecure = false. "
        "In the portal, navigate to Ingress and uncheck 'Allow insecure connections'."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "not_null", "path": "properties.configuration.ingress"},
            {"op": "eq", "path": "properties.configuration.ingress.allowInsecure", "value": True},
        ],
    },
)

# RE-04 — Container App minimum replicas = 0
REL_CA_001 = _rule(
    rule_id="REL-CA-001",
    pillar="reliability",
    resource_types=["microsoft.app/containerapps"],
    evaluation_type="deterministic",
    severity="medium",
    title="Container App minimum replica count is zero (can scale to zero)",
    description=(
        "A minimum replica count of zero allows the Container App to scale to zero "
        "under low load, causing a cold-start delay when traffic resumes. For "
        "production workloads that require low latency or high availability, at least "
        "one replica should always be running."
    ),
    recommendation=(
        "Set a minimum replica count of at least 1 for production Container Apps: "
        "properties.template.scale.minReplicas = 1. Consider matching the number of "
        "Availability Zones in the region for full zone resilience."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.template.scale.minReplicas"},
            {"op": "eq", "path": "properties.template.scale.minReplicas", "value": 0},
        ],
    },
)

# OE-07 — Container App has no managed identity
OPS_CA_001 = _rule(
    rule_id="OPS-CA-001",
    pillar="operational_excellence",
    resource_types=["microsoft.app/containerapps"],
    evaluation_type="deterministic",
    severity="low",
    title="Container App has no managed identity assigned",
    description=(
        "Without a managed identity, Container Apps must rely on credentials, connection "
        "strings, or SAS tokens stored in environment variables or secret stores to "
        "authenticate against Azure services. Managed identities eliminate the need to "
        "manage credentials and enable seamless integration with Azure AD-protected services."
    ),
    recommendation=(
        "Enable system-assigned managed identity: properties.identity.type = SystemAssigned, "
        "or assign a user-assigned identity. Then grant the identity the minimum required "
        "RBAC roles on target services (Key Vault, Storage, Service Bus, etc.)."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "identity"},
            {"op": "eq", "path": "identity.type", "value": "None"},
        ],
    },
)

# ---------------------------------------------------------------------------
# Reliability — Availability Sets
# ---------------------------------------------------------------------------

# RE-04 — Availability Set not Aligned (Classic/unmanaged)
REL_AVSET_001 = _rule(
    rule_id="REL-AVSET-001",
    pillar="reliability",
    resource_types=["microsoft.compute/availabilitysets"],
    evaluation_type="deterministic",
    severity="medium",
    title="Availability Set is using Classic (unmanaged-disk) configuration",
    description=(
        "Classic (non-Aligned) Availability Sets are incompatible with Azure Managed "
        "Disks. VMs in Classic availability sets use unmanaged disks stored in storage "
        "accounts, which do not automatically distribute across fault domains. This "
        "reduces the failure isolation benefit that availability sets are designed to provide."
    ),
    recommendation=(
        "Recreate the Availability Set with sku.name = Aligned and migrate VMs to use "
        "Azure Managed Disks. Use az vm convert --name <vm> --resource-group <rg> to "
        "convert existing unmanaged-disk VMs."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "sku.name"},
            {"op": "ne", "path": "sku.name", "value": "Aligned"},
        ],
    },
)

# RE-04 — Availability Set fault domains < 2
REL_AVSET_002 = _rule(
    rule_id="REL-AVSET-002",
    pillar="reliability",
    resource_types=["microsoft.compute/availabilitysets"],
    evaluation_type="deterministic",
    severity="medium",
    title="Availability Set fault domain count is below 2",
    description=(
        "Fault domains separate VMs across different power sources and network switches. "
        "A fault domain count below 2 means multiple VMs in the set share the same "
        "hardware rack, eliminating the hardware-failure isolation that availability "
        "sets are designed to provide."
    ),
    recommendation=(
        "Recreate the Availability Set with platformFaultDomainCount >= 2 (3 is optimal "
        "in most regions). VMs cannot be moved across fault domains without recreation."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.platformFaultDomainCount"},
            {"op": "lt", "path": "properties.platformFaultDomainCount", "value": 2},
        ],
    },
)

# ---------------------------------------------------------------------------
# Security & Reliability — SQL Managed Instance
# ---------------------------------------------------------------------------

# SE-06 — SQL MI public data endpoint enabled
SEC_SQLMI_001 = _rule(
    rule_id="SEC-SQLMI-001",
    pillar="security",
    resource_types=["microsoft.sql/managedinstances"],
    evaluation_type="deterministic",
    severity="high",
    title="SQL Managed Instance public data endpoint is enabled",
    description=(
        "Enabling the public data endpoint on SQL Managed Instance exposes the "
        "instance to inbound connections from the public internet on port 3342. "
        "While TLS encryption is enforced, exposing the endpoint significantly "
        "increases the attack surface and risk of credential-based attacks."
    ),
    recommendation=(
        "Disable the public data endpoint: az sql mi update --public-data-endpoint-enabled false "
        "--name <mi> --resource-group <rg>. Connect via the private VNet endpoint or "
        "through a VPN/ExpressRoute connection."
    ),
    condition_dsl={"op": "eq", "path": "properties.publicDataEndpointEnabled", "value": True},
)

# SE-07 — SQL MI minimum TLS version < 1.2
SEC_SQLMI_002 = _rule(
    rule_id="SEC-SQLMI-002",
    pillar="security",
    resource_types=["microsoft.sql/managedinstances"],
    evaluation_type="deterministic",
    severity="high",
    title="SQL Managed Instance minimum TLS version is below 1.2",
    description=(
        "TLS 1.0 and 1.1 have known cryptographic weaknesses including POODLE and BEAST "
        "vulnerabilities. Allowing these legacy versions on SQL Managed Instance exposes "
        "database connections to potential downgrade attacks and eavesdropping."
    ),
    recommendation=(
        "Set the minimum TLS version to 1.2: az sql mi update --minimal-tls-version 1.2 "
        "--name <mi> --resource-group <rg>. Test all client drivers for TLS 1.2 support "
        "before enforcing."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.minimalTlsVersion"},
            {"op": "not_in", "path": "properties.minimalTlsVersion", "value": ["1.2", "1.3"]},
        ],
    },
)

# RE-04 — SQL MI not zone-redundant
REL_SQLMI_001 = _rule(
    rule_id="REL-SQLMI-001",
    pillar="reliability",
    resource_types=["microsoft.sql/managedinstances"],
    evaluation_type="deterministic",
    severity="medium",
    title="SQL Managed Instance is not configured for zone redundancy",
    description=(
        "Without zone redundancy, SQL Managed Instance is deployed in a single "
        "Availability Zone. An AZ failure would make the instance temporarily "
        "unavailable. Zone-redundant deployment spreads replicas across AZs and "
        "provides transparent failover within the SLA."
    ),
    recommendation=(
        "Enable zone redundancy for the SQL Managed Instance. This requires the "
        "Business Critical tier. Set properties.zoneRedundant = true during creation "
        "or via update operations."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.zoneRedundant"},
            {"op": "eq", "path": "properties.zoneRedundant", "value": False},
        ],
    },
)

# ---------------------------------------------------------------------------
# Security — Event Grid Topics
# ---------------------------------------------------------------------------

# SE-06 — Event Grid topic allows public network access
SEC_EG_001 = _rule(
    rule_id="SEC-EG-001",
    pillar="security",
    resource_types=["microsoft.eventgrid/topics"],
    evaluation_type="deterministic",
    severity="medium",
    title="Event Grid topic allows public network access",
    description=(
        "When public network access is enabled on an Event Grid topic, the topic "
        "endpoint is reachable from any network. This increases the attack surface "
        "for event injection attacks and may allow unauthorized systems to subscribe "
        "to or publish events. Restricting to private endpoints ensures only "
        "authorized VNet-connected resources can interact with the topic."
    ),
    recommendation=(
        "Disable public network access: az eventgrid topic update "
        "--public-network-access Disabled --name <topic> --resource-group <rg>. "
        "Deploy a private endpoint for the topic and configure DNS to resolve to "
        "the private IP."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.publicNetworkAccess"},
            {"op": "eq", "path": "properties.publicNetworkAccess", "value": "Enabled"},
        ],
    },
)

# SE-01 / SE-02 — Event Grid local auth (SAS key) not disabled
SEC_EG_002 = _rule(
    rule_id="SEC-EG-002",
    pillar="security",
    resource_types=["microsoft.eventgrid/topics"],
    evaluation_type="deterministic",
    severity="medium",
    title="Event Grid topic local authentication (SAS keys) is not disabled",
    description=(
        "Local authentication using Shared Access Signatures (SAS keys) bypasses Azure "
        "Active Directory authentication and cannot leverage Conditional Access, PIM, "
        "or fine-grained RBAC controls. Disabling local auth forces all clients to use "
        "Azure AD-based authentication (Managed Identity or service principal)."
    ),
    recommendation=(
        "Disable local authentication: az eventgrid topic update --disable-local-auth true "
        "--name <topic> --resource-group <rg>. Update event publishers to authenticate "
        "using Managed Identity or a service principal with the EventGrid Data Sender role."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.disableLocalAuth"},
            {"op": "eq", "path": "properties.disableLocalAuth", "value": False},
        ],
    },
)

# ---------------------------------------------------------------------------
# OE & Cost — Application Insights
# ---------------------------------------------------------------------------

# OE-07 / OE-10 — Application Insights using classic (non-workspace-based) mode
OPS_AI_001 = _rule(
    rule_id="OPS-AI-001",
    pillar="operational_excellence",
    resource_types=["microsoft.insights/components"],
    evaluation_type="deterministic",
    severity="medium",
    title="Application Insights is using classic (non-workspace-based) mode",
    description=(
        "Classic Application Insights stores telemetry in its own proprietary data store "
        "that is separate from Log Analytics. Workspace-based mode unifies application "
        "and infrastructure telemetry in a single Log Analytics workspace, enabling "
        "cross-resource queries, unified RBAC, and cost consolidation. Classic mode "
        "is deprecated and scheduled for retirement."
    ),
    recommendation=(
        "Migrate to workspace-based Application Insights by linking to an existing "
        "Log Analytics workspace: set properties.WorkspaceResourceId to the workspace "
        "resource ID. Use the Azure Portal migration wizard or update the ARM template."
    ),
    condition_dsl={"op": "is_null", "path": "properties.WorkspaceResourceId"},
)

# CO-06 — Application Insights retention above 90 days
CST_AI_001 = _rule(
    rule_id="CST-AI-001",
    pillar="cost_optimization",
    resource_types=["microsoft.insights/components"],
    evaluation_type="deterministic",
    severity="low",
    title="Application Insights retention is configured above 90 days",
    description=(
        "Application Insights charges for data retention beyond the free 90-day tier. "
        "Extending retention to 180, 365, or more days significantly increases monthly "
        "telemetry storage costs. For long-term retention requirements, exporting data "
        "to Azure Storage or Log Analytics is more cost-effective."
    ),
    recommendation=(
        "Review whether extended retention is genuinely required. For compliance or "
        "audit needs, configure continuous export to Azure Storage (blob) or Blob "
        "Lifecycle Management policies for cold-tier archival. Reset RetentionInDays "
        "to 90 to eliminate the excess retention charge."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {"op": "not_null", "path": "properties.RetentionInDays"},
            {"op": "gt", "path": "properties.RetentionInDays", "value": 90},
        ],
    },
)

# ---------------------------------------------------------------------------
# OE — Action Groups
# ---------------------------------------------------------------------------

# OE-07 / OE-08 — Action Group has no email or webhook receivers
OPS_AG_001 = _rule(
    rule_id="OPS-AG-001",
    pillar="operational_excellence",
    resource_types=["microsoft.insights/actiongroups"],
    evaluation_type="deterministic",
    severity="medium",
    title="Action Group has no email or webhook receivers configured",
    description=(
        "An Action Group with no email or webhook receivers cannot reliably notify "
        "on-call engineers when an alert fires. While other receiver types (SMS, Logic "
        "App, Function, ITSM) are valid, email and webhook are the most universally "
        "actionable. An action group that silently discards alert notifications "
        "undermines the entire alerting strategy."
    ),
    recommendation=(
        "Add at least one email or webhook receiver to each Action Group. For incident "
        "management integration, configure a webhook pointing to PagerDuty, Opsgenie, "
        "or a custom Azure Function. Verify receivers are reachable by triggering a "
        "test notification from the portal."
    ),
    condition_dsl={
        "op": "and",
        "conditions": [
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "properties.emailReceivers"},
                    {"op": "length_eq", "path": "properties.emailReceivers", "value": 0},
                ],
            },
            {
                "op": "or",
                "conditions": [
                    {"op": "is_null", "path": "properties.webhookReceivers"},
                    {"op": "length_eq", "path": "properties.webhookReceivers", "value": 0},
                ],
            },
        ],
    },
)

# ---------------------------------------------------------------------------
# Security — App Service (expanded)
# ---------------------------------------------------------------------------

# SE-07 — App Service HTTPS-only not enforced
SEC_APP_005 = _rule(
    rule_id="SEC-APP-005",
    pillar="security",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="high",
    title="App Service HTTPS-only enforcement is disabled",
    description=(
        "Without HTTPS-only enforcement, clients can connect to the App Service over "
        "unencrypted HTTP. This exposes session tokens, API keys, and sensitive data "
        "to network eavesdropping. Azure App Service supports automatic HTTP-to-HTTPS "
        "redirection at the platform level with no application code change required."
    ),
    recommendation=(
        "Enable httpsOnly on the App Service: "
        "az webapp update --https-only true --name <app> --resource-group <rg>. "
        "This redirects all HTTP traffic to HTTPS at the Azure ingress layer."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.httpsOnly"},
            {"op": "eq", "path": "properties.httpsOnly", "value": False},
        ],
    },
)

# SE-07 — App Service minimum TLS version below 1.2
SEC_APP_006 = _rule(
    rule_id="SEC-APP-006",
    pillar="security",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="high",
    title="App Service minimum TLS version is below 1.2",
    description=(
        "TLS 1.0 and 1.1 contain known vulnerabilities (POODLE, BEAST) and are "
        "considered insecure. Allowing legacy TLS versions on App Service exposes "
        "client connections to protocol downgrade attacks and may violate PCI-DSS, "
        "HIPAA, and other compliance standards that mandate TLS 1.2 or higher."
    ),
    recommendation=(
        "Set the minimum TLS version to 1.2 in the App Service configuration: "
        "az webapp config set --min-tls-version 1.2 --name <app> --resource-group <rg>. "
        "Validate that all clients and downstream services support TLS 1.2."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.siteConfig.minTlsVersion"},
            {
                "op": "not_in",
                "path": "properties.siteConfig.minTlsVersion",
                "value": ["1.2", "1.3"],
            },
        ],
    },
)

# SE-01 — App Service has no managed identity
SEC_APP_007 = _rule(
    rule_id="SEC-APP-007",
    pillar="security",
    resource_types=["microsoft.web/sites"],
    evaluation_type="deterministic",
    severity="medium",
    title="App Service has no managed identity assigned",
    description=(
        "Without a managed identity, the application must store and manage credentials "
        "(connection strings, API keys, certificates) to authenticate against Azure "
        "services such as Key Vault, Storage, and SQL. Managed identities eliminate "
        "credential management and reduce the blast radius of a credential compromise."
    ),
    recommendation=(
        "Enable system-assigned managed identity: "
        "az webapp identity assign --name <app> --resource-group <rg>. "
        "Then grant the identity the minimum required RBAC roles on dependent services "
        "and update the application to use DefaultAzureCredential."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "identity"},
            {"op": "eq", "path": "identity.type", "value": "None"},
        ],
    },
)

# ---------------------------------------------------------------------------
# Security — Virtual Machines (expanded)
# ---------------------------------------------------------------------------

# SE-01 — VM has no managed identity
SEC_VM_004 = _rule(
    rule_id="SEC-VM-004",
    pillar="security",
    resource_types=["microsoft.compute/virtualmachines"],
    evaluation_type="deterministic",
    severity="medium",
    title="Virtual Machine has no managed identity assigned",
    description=(
        "Without a managed identity, workloads running on the VM must use credentials "
        "stored in configuration files, environment variables, or code to access Azure "
        "services. This increases the risk of credential exposure through disk snapshots, "
        "memory dumps, or misconfigured logging. Managed identities provide automatic "
        "credential rotation at the platform level."
    ),
    recommendation=(
        "Enable system-assigned managed identity: "
        "az vm identity assign --name <vm> --resource-group <rg>. "
        "Update application code to use DefaultAzureCredential from the Azure SDK, "
        "which automatically uses the VM identity when running on Azure."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "identity"},
            {"op": "eq", "path": "identity.type", "value": "None"},
        ],
    },
)

# ---------------------------------------------------------------------------
# Security — AKS (expanded)
# ---------------------------------------------------------------------------

# SE-01 / SE-02 — AKS RBAC not enabled
SEC_AKS_001 = _rule(
    rule_id="SEC-AKS-001",
    pillar="security",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="high",
    title="AKS cluster does not have Kubernetes RBAC enabled",
    description=(
        "Without Kubernetes RBAC, all authenticated users have unrestricted access to "
        "cluster resources. This violates the principle of least privilege and makes it "
        "impossible to enforce role-based access control for namespaced workloads, "
        "CI/CD pipelines, and developer access. Kubernetes RBAC is the foundation of "
        "AKS access control and should always be enabled."
    ),
    recommendation=(
        "Enable RBAC during AKS cluster creation: --enable-rbac flag in az aks create. "
        "For existing clusters, RBAC cannot be enabled post-creation without recreation. "
        "Also enable Azure AD integration for centralized identity: --enable-azure-rbac."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {"op": "is_null", "path": "properties.enableRBAC"},
            {"op": "eq", "path": "properties.enableRBAC", "value": False},
        ],
    },
)

# SE-06 — AKS API server not private
SEC_AKS_002 = _rule(
    rule_id="SEC-AKS-002",
    pillar="security",
    resource_types=["microsoft.containerservice/managedclusters"],
    evaluation_type="deterministic",
    severity="medium",
    title="AKS cluster API server is publicly accessible",
    description=(
        "A public AKS API server endpoint is reachable from the internet, exposing "
        "the Kubernetes control plane to brute-force and credential stuffing attacks. "
        "While RBAC and Azure AD authentication are additional layers of defence, "
        "a private cluster eliminates internet-based access entirely by placing the "
        "API server on a private IP accessible only within the VNet."
    ),
    recommendation=(
        "Enable private cluster mode: --enable-private-cluster in az aks create. "
        "If a fully private cluster is not feasible, restrict API server access to "
        "specific IP ranges using --api-server-authorized-ip-ranges."
    ),
    condition_dsl={
        "op": "or",
        "conditions": [
            {
                "op": "is_null",
                "path": "properties.apiServerAccessProfile.enablePrivateCluster",
            },
            {
                "op": "eq",
                "path": "properties.apiServerAccessProfile.enablePrivateCluster",
                "value": False,
            },
        ],
    },
)


# ===========================================================================
# Public catalogue — all new rules in insertion order
# ===========================================================================

NEW_RULES: list[dict[str, Any]] = [
    # Security (Phase 3)
    SEC_CR_001,
    SEC_DEF_001,
    SEC_NET_004,
    # Reliability (Phase 3)
    REL_AGW_002,
    REL_SB_001,
    REL_ASR_001,
    # Reliability (Phase 4 — expanded coverage)
    REL_STOR_004,
    REL_LB_002,
    REL_COSMOS_001,
    REL_AKS_001,
    REL_APP_004,
    REL_EH_001,
    REL_MYSQL_001,
    REL_POSTGRES_001,
    REL_REDIS_001,
    REL_AGW_003,
    # Operational Excellence (Phase 3)
    OPS_DIAG_001,
    OPS_SLOT_001,
    OPS_MON_001,
    # Performance Efficiency (Phase 3)
    PER_ALERT_001,
    PER_ADV_001,
    PER_LT_001,
    # Cost Optimization (Phase 3)
    CST_BUDGET_001,
    CST_COST_TAG_001,
    CST_ADV_001,
    # Cost Optimization (Phase 5 — expanded coverage)
    CST_STOR_003,
    CST_APP_001,
    CST_SNAP_001,
    CST_NIC_001,
    CST_LOG_001,
    CST_SCALE_001,
    CST_PREM_001,
    CST_AKS_001,
    CST_AGW_002,
    CST_GW_001,
    CST_SQL_002,
    CST_COSMOS_001,
    # Operational Excellence (Phase 6 — expanded coverage)
    OPS_AKS_001,
    OPS_AKS_002,
    OPS_NSG_001,
    OPS_COSMOS_001,
    OPS_STOR_001,
    OPS_VMSS_001,
    OPS_REDIS_001,
    OPS_APP_003,
    OPS_MYSQL_001,
    OPS_POSTGRES_001,
    OPS_ACT_001,
    OPS_SQL_003,
    # Performance Efficiency (Phase 7 — expanded coverage)
    PER_VM_004,
    PER_DISK_001,
    PER_APP_004,
    PER_APP_005,
    PER_SQL_002,
    PER_REDIS_001,
    PER_LB_001,
    PER_AGW_001,
    PER_CDN_002,
    PER_SQL_003,
    PER_COSMOS_001,
    PER_AKS_001,
    # Phase 8 — Cross-pillar resource coverage expansion
    # Security: Key Vault, Azure Firewall, Container Apps, SQL MI, Event Grid,
    #           App Service (expanded), VMs (expanded), AKS (expanded)
    SEC_KV_006,
    SEC_KV_007,
    SEC_AFW_001,
    SEC_CA_001,
    SEC_SQLMI_001,
    SEC_SQLMI_002,
    SEC_EG_001,
    SEC_EG_002,
    SEC_APP_005,
    SEC_APP_006,
    SEC_APP_007,
    SEC_VM_004,
    SEC_AKS_001,
    SEC_AKS_002,
    # Reliability: Key Vault, Virtual Network, Azure Firewall, Container Apps,
    #              Availability Sets, SQL MI
    REL_KV_001,
    REL_VNET_001,
    REL_AFW_001,
    REL_CA_001,
    REL_AVSET_001,
    REL_AVSET_002,
    REL_SQLMI_001,
    # Operational Excellence: Virtual Network, Container Apps, Application Insights,
    #                         Action Groups
    OPS_VNET_001,
    OPS_CA_001,
    OPS_AI_001,
    OPS_AG_001,
    # Cost Optimization: Application Insights
    CST_AI_001,
]

# Controls these rules newly cover (informational — used by the seed script summary)
NEWLY_COVERED_CONTROLS: list[str] = [
    # Phase 3
    "SE-02",
    "OE-02",  # SEC-CR-001
    "SE-02",
    "SE-09",  # SEC-DEF-001
    "SE-06",  # SEC-NET-004
    "RE-04",  # REL-AGW-002
    "RE-06",  # REL-SB-001
    "RE-09",  # REL-ASR-001
    "OE-08",  # OPS-DIAG-001
    "OE-09",
    "OE-11",  # OPS-SLOT-001
    "OE-10",
    "PE-04",  # OPS-MON-001
    "PE-01",  # PER-ALERT-001
    "PE-03",
    "PE-09",  # PER-ADV-001
    "PE-12",  # PER-LT-001
    "CO-01",
    "CO-04",  # CST-BUDGET-001
    "CO-02",  # CST-COST-TAG-001
    "CO-08",
    "CO-12",  # CST-ADV-001
    # Phase 4 — Reliability expansion
    "RE-08",  # REL-STOR-004
    "RE-04",
    "RE-05",  # REL-LB-002
    "RE-02",
    "RE-03",  # REL-COSMOS-001
    "RE-02",  # REL-AKS-001
    "RE-02",  # REL-APP-004
    "RE-06",  # REL-EH-001
    "RE-02",
    "RE-08",  # REL-MYSQL-001
    "RE-02",
    "RE-08",  # REL-POSTGRES-001
    "RE-02",  # REL-REDIS-001
    "RE-02",  # REL-AGW-003
    # Phase 5 — Cost Optimization expansion
    "CO-07",
    "CO-10",  # CST-STOR-003
    "CO-06",  # CST-APP-001
    "CO-07",  # CST-SNAP-001
    "CO-07",  # CST-NIC-001
    "CO-07",
    "CO-10",  # CST-LOG-001
    "CO-05",  # CST-SCALE-001
    "CO-06",  # CST-PREM-001
    "CO-05",  # CST-AKS-001
    "CO-06",  # CST-AGW-002
    "CO-06",  # CST-GW-001
    "CO-06",  # CST-SQL-002
    "CO-06",  # CST-COSMOS-001
    # Phase 6 — Operational Excellence expansion
    "OE-07",
    "OE-10",  # OPS-AKS-001
    "OE-12",  # OPS-AKS-002
    "OE-07",  # OPS-NSG-001
    "OE-07",
    "OE-08",  # OPS-COSMOS-001
    "OE-08",  # OPS-STOR-001
    "OE-12",  # OPS-VMSS-001
    "OE-07",
    "OE-08",  # OPS-REDIS-001
    "OE-09",
    "OE-11",  # OPS-APP-003
    "OE-08",  # OPS-MYSQL-001
    "OE-08",  # OPS-POSTGRES-001
    "OE-07",
    "OE-10",  # OPS-ACT-001
    "OE-07",
    "OE-10",  # OPS-SQL-003
    # Phase 7 — Performance Efficiency expansion
    "PE-05",
    "PE-07",  # PER-VM-004
    "PE-05",  # PER-DISK-001
    "PE-05",
    "PE-06",  # PER-APP-004
    "PE-06",  # PER-APP-005
    "PE-08",  # PER-SQL-002
    "PE-11",  # PER-REDIS-001
    "PE-05",  # PER-LB-001
    "PE-05",  # PER-AGW-001
    "PE-10",  # PER-CDN-002
    "PE-08",
    "PE-09",  # PER-SQL-003
    "PE-08",  # PER-COSMOS-001
    "PE-05",  # PER-AKS-001
    # Phase 8 — Cross-pillar resource coverage expansion
    "SE-01",
    "SE-02",  # SEC-KV-006
    "SE-06",  # SEC-KV-007
    "SE-09",  # SEC-AFW-001
    "SE-07",  # SEC-CA-001
    "SE-06",  # SEC-SQLMI-001
    "SE-07",  # SEC-SQLMI-002
    "SE-06",  # SEC-EG-001
    "SE-01",
    "SE-02",  # SEC-EG-002
    "SE-07",  # SEC-APP-005
    "SE-07",  # SEC-APP-006
    "SE-01",  # SEC-APP-007
    "SE-01",  # SEC-VM-004
    "SE-01",
    "SE-02",  # SEC-AKS-001
    "SE-06",  # SEC-AKS-002
    "RE-06",  # REL-KV-001
    "RE-04",
    "RE-05",  # REL-VNET-001
    "RE-04",  # REL-AFW-001
    "RE-04",  # REL-CA-001
    "RE-04",  # REL-AVSET-001
    "RE-04",  # REL-AVSET-002
    "RE-04",  # REL-SQLMI-001
    "OE-07",  # OPS-VNET-001
    "OE-07",  # OPS-CA-001
    "OE-07",
    "OE-10",  # OPS-AI-001
    "OE-07",
    "OE-08",  # OPS-AG-001
    "CO-06",  # CST-AI-001
]

HUMAN_REVIEW_REQUIRED: list[str] = [
    "SE-10",  # Conduct regular adversarial testing — no ARM-detectable evidence
    "OE-03",  # Formalize software ideation / planning — organizational process only
    "OE-04",  # Use continuous integration — CI pipelines are not ARM resources
    "CO-09",  # Optimize personnel time — no objective Azure API measure
]
