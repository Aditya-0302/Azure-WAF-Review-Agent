"""Rule-driven remediation detail templates for report enrichment.

Each template covers 7 dimensions per finding:
  1. Business Impact     — organisational / financial consequence
  2. Technical Risk      — infrastructure / security risk vector
  3. Azure CLI           — az-cli commands to remediate
  4. Bicep               — Bicep resource snippet
  5. Terraform           — Terraform resource snippet
  6. Estimated Effort    — implementation time estimate
  7. Risk Reduction      — expected compliance improvement after fix

Templates are keyed by rule_id.  Unknown rule_ids fall back to pillar+severity
derived defaults so every finding always receives complete remediation metadata.

Architecture notes:
  - Add new templates by calling _register() with the rule_id and 7 kwargs.
  - Fallback logic lives in get_remediation_detail(); no caller changes needed.
  - This module is reporting-only: it does NOT touch the assessment pipeline,
    database, or API layers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemediationDetail:
    """Complete remediation metadata for one finding / rule."""

    business_impact: str
    technical_risk: str
    azure_cli: str
    bicep: str
    terraform: str
    estimated_effort: str
    risk_reduction: str


# ---------------------------------------------------------------------------
# Template registry — keyed by rule_id
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, RemediationDetail] = {}


def _register(rule_id: str, **kwargs: str) -> None:
    _TEMPLATES[rule_id] = RemediationDetail(**kwargs)


# ===========================================================================
# SECURITY
# ===========================================================================

_register(
    "SEC-CR-001",
    business_impact=(
        "Unsigned container images can introduce malicious or tampered code into "
        "production workloads, risking data breaches, compliance violations (PCI-DSS, "
        "SOC 2), and supply-chain compromise at scale."
    ),
    technical_risk=(
        "Without content trust, any image — including compromised or counterfeit tags "
        "— can be pulled and executed, bypassing image provenance guarantees and "
        "enabling a supply-chain attack via registry poisoning."
    ),
    azure_cli=(
        "az acr config content-trust update \\\n"
        "  --name <registry-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --status enabled"
    ),
    bicep=(
        "resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {\n"
        "  name: registryName\n"
        "  location: location\n"
        "  sku: { name: 'Premium' }\n"
        "  properties: {\n"
        "    policies: {\n"
        "      trustPolicy: {\n"
        "        status: 'enabled'\n"
        "        type: 'Notary'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_container_registry" "acr" {\n'
        '  name                = var.registry_name\n'
        '  resource_group_name = var.resource_group_name\n'
        '  location            = var.location\n'
        '  sku                 = "Premium"\n'
        "  trust_policy {\n"
        "    enabled = true\n"
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~30 min)",
    risk_reduction="High (50-70% supply-chain risk reduction)",
)

_register(
    "SEC-DEF-001",
    business_impact=(
        "Workloads without Defender Standard lack runtime threat detection and "
        "vulnerability assessment, increasing attacker dwell time and exposure to "
        "regulatory penalties for unmonitored production systems."
    ),
    technical_risk=(
        "Free-tier Defender provides no advanced threat detection, adaptive application "
        "controls, or just-in-time VM access — leaving resources exposed to known "
        "attack patterns and zero-day exploitation."
    ),
    azure_cli=(
        "# Enable Standard for the affected workload type (e.g. Containers)\n"
        "az security pricing create \\\n"
        "  --name Containers \\\n"
        "  --tier Standard\n\n"
        "# Repeat for each plan: VirtualMachines, SqlServers, Storage, AppService, KeyVaults"
    ),
    bicep=(
        "resource defenderPlan 'Microsoft.Security/pricings@2023-01-01' = {\n"
        "  name: 'Containers'\n"
        "  properties: {\n"
        "    pricingTier: 'Standard'\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_security_center_subscription_pricing" "defender" {\n'
        '  tier          = "Standard"\n'
        '  resource_type = "Containers"\n'
        "}"
    ),
    estimated_effort="Low (~15 min per Defender plan)",
    risk_reduction="High (60-80% threat detection coverage improvement)",
)

_register(
    "SEC-NET-004",
    business_impact=(
        "App Service outbound traffic over the public internet increases the attack "
        "surface for data exfiltration and man-in-the-middle interception of calls to "
        "databases, Key Vaults, and internal APIs."
    ),
    technical_risk=(
        "Without VNet integration, back-end services must expose public endpoints, "
        "making network-layer isolation impossible and violating the platform "
        "responsibility boundary (SE-06)."
    ),
    azure_cli=(
        "az webapp vnet-integration add \\\n"
        "  --name <app-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --vnet <vnet-name> \\\n"
        "  --subnet <subnet-name>\n\n"
        "# Route all outbound traffic through VNet\n"
        "az webapp config set \\\n"
        "  --name <app-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --generic-configurations '{\"vnetRouteAllEnabled\": true}'"
    ),
    bicep=(
        "resource appService 'Microsoft.Web/sites@2023-01-01' = {\n"
        "  name: appName\n"
        "  properties: {\n"
        "    virtualNetworkSubnetId: subnetId\n"
        "    vnetRouteAllEnabled: true\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_app_service_virtual_network_swift_connection" "vnet" {\n'
        "  app_service_id = azurerm_linux_web_app.app.id\n"
        "  subnet_id      = azurerm_subnet.app.id\n"
        "}"
    ),
    estimated_effort="Medium (~2-4 hours including subnet delegation)",
    risk_reduction="High (40-60% network attack surface reduction)",
)

# ===========================================================================
# RELIABILITY
# ===========================================================================

_register(
    "REL-AGW-002",
    business_impact=(
        "Traffic routed to application-dead back-end instances causes user-facing "
        "errors and degrades service availability, potentially breaching SLAs and "
        "causing revenue loss during high-traffic periods."
    ),
    technical_risk=(
        "Default TCP probes do not validate application-layer readiness; an instance "
        "that is network-alive but application-crashed continues receiving live traffic "
        "until the TCP probe timeout fires, causing cascading user errors."
    ),
    azure_cli=(
        "# Create a custom HTTP health probe\n"
        "az network application-gateway probe create \\\n"
        "  --gateway-name <gateway-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --name AppHealthProbe \\\n"
        "  --protocol Http \\\n"
        "  --host-name-from-http-settings true \\\n"
        "  --path /health \\\n"
        "  --interval 30 \\\n"
        "  --timeout 30 \\\n"
        "  --threshold 3\n\n"
        "# Associate the probe with each HTTP backend setting\n"
        "az network application-gateway http-settings update \\\n"
        "  --gateway-name <gateway-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --name <http-setting-name> \\\n"
        "  --probe AppHealthProbe"
    ),
    bicep=(
        "resource appGw 'Microsoft.Network/applicationGateways@2023-09-01' = {\n"
        "  properties: {\n"
        "    probes: [\n"
        "      {\n"
        "        name: 'AppHealthProbe'\n"
        "        properties: {\n"
        "          protocol: 'Http'\n"
        "          path: '/health'\n"
        "          interval: 30\n"
        "          timeout: 30\n"
        "          unhealthyThreshold: 3\n"
        "          pickHostNameFromBackendHttpSettings: true\n"
        "        }\n"
        "      }\n"
        "    ]\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_application_gateway" "agw" {\n'
        "  probe {\n"
        '    name                                      = "AppHealthProbe"\n'
        '    protocol                                  = "Http"\n'
        '    path                                      = "/health"\n'
        "    interval                                  = 30\n"
        "    timeout                                   = 30\n"
        "    unhealthy_threshold                       = 3\n"
        "    pick_host_name_from_backend_http_settings = true\n"
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~1 hour)",
    risk_reduction="Medium (30-50% reduction in traffic-to-dead-instance incidents)",
)

_register(
    "REL-SB-001",
    business_impact=(
        "Basic-tier Service Bus cannot handle poison messages via dead-letter queues, "
        "risking message loss and processing pipeline failures that can disrupt order "
        "processing, notifications, or integration workflows."
    ),
    technical_risk=(
        "Without DLQs, failed messages block queue processing or are silently dropped; "
        "topics and fan-out patterns are architecturally unavailable on Basic tier, "
        "limiting resilient loose-coupling designs."
    ),
    azure_cli=(
        "az servicebus namespace update \\\n"
        "  --name <namespace-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --sku Standard\n\n"
        "# For mission-critical workloads, use Premium with zone redundancy:\n"
        "# --sku Premium --zone-redundant true"
    ),
    bicep=(
        "resource sbNamespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {\n"
        "  name: namespaceName\n"
        "  location: location\n"
        "  sku: {\n"
        "    name: 'Standard'\n"
        "    tier: 'Standard'\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_servicebus_namespace" "sb" {\n'
        "  name                = var.namespace_name\n"
        "  location            = var.location\n"
        "  resource_group_name = var.resource_group_name\n"
        '  sku                 = "Standard"\n'
        "}"
    ),
    estimated_effort="Low (~30 min, plus application validation)",
    risk_reduction="Medium (40-60% reliability improvement for messaging pipelines)",
)

_register(
    "REL-ASR-001",
    business_impact=(
        "Without cross-region restore, a regional Azure outage blocks recovery "
        "operations entirely, extending RTO beyond acceptable limits and risking "
        "permanent data loss when backups are constrained to the failed region."
    ),
    technical_risk=(
        "GRS/RA-GRS replication copies vault data to a secondary region, but "
        "cross-region restore must be explicitly enabled before a DR event — it "
        "cannot be activated retroactively during an active regional outage."
    ),
    azure_cli=(
        "# Step 1: Ensure vault uses GRS redundancy\n"
        "az backup vault backup-properties set \\\n"
        "  --name <vault-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --backup-storage-redundancy GeoRedundant\n\n"
        "# Step 2: Enable cross-region restore\n"
        "az backup vault backup-properties set \\\n"
        "  --name <vault-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --cross-region-restore-flag true"
    ),
    bicep=(
        "resource vault 'Microsoft.RecoveryServices/vaults@2023-08-01' = {\n"
        "  name: vaultName\n"
        "  location: location\n"
        "  sku: { name: 'RS0', tier: 'Standard' }\n"
        "  properties: {\n"
        "    redundancySettings: {\n"
        "      storageModelType: 'GeoRedundant'\n"
        "      crossRegionRestore: 'Enabled'\n"
        "    }\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_recovery_services_vault" "vault" {\n'
        "  name                         = var.vault_name\n"
        "  location                     = var.location\n"
        "  resource_group_name          = var.resource_group_name\n"
        '  sku                          = "Standard"\n'
        '  storage_mode_type            = "GeoRedundant"\n'
        "  cross_region_restore_enabled = true\n"
        "}"
    ),
    estimated_effort="Low (~30 min)",
    risk_reduction="High (70-90% DR recovery capability improvement)",
)

# ===========================================================================
# OPERATIONAL EXCELLENCE
# ===========================================================================

_register(
    "OPS-DIAG-001",
    business_impact=(
        "Disabled boot diagnostics means engineers have no serial console or "
        "screenshot evidence when a VM fails to start after a patch or deployment, "
        "extending MTTR and delaying restoration of critical business services."
    ),
    technical_risk=(
        "Without boot diagnostics, post-change VM startup failure diagnosis requires "
        "downtime-extending guesswork; there is no audit trail to support "
        "change-management root-cause analysis."
    ),
    azure_cli=(
        "# Enable boot diagnostics (managed storage — recommended)\n"
        "az vm boot-diagnostics enable \\\n"
        "  --name <vm-name> \\\n"
        "  --resource-group <resource-group>\n\n"
        "# Retrieve boot log after a failure:\n"
        "az vm boot-diagnostics get-boot-log \\\n"
        "  --name <vm-name> \\\n"
        "  --resource-group <resource-group>"
    ),
    bicep=(
        "resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {\n"
        "  properties: {\n"
        "    diagnosticsProfile: {\n"
        "      bootDiagnostics: {\n"
        "        enabled: true\n"
        "        // Omit storageUri to use managed storage\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_linux_virtual_machine" "vm" {\n'
        "  # ... other configuration ...\n"
        "  boot_diagnostics {\n"
        "    # Empty block enables Azure-managed boot diagnostics\n"
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~15 min per VM)",
    risk_reduction="Low-Medium (20-35% MTTR reduction for VM boot failures)",
)

_register(
    "OPS-SLOT-001",
    business_impact=(
        "Without deployment slots, every production release causes downtime or "
        "cold-swap restarts, increasing the blast radius of failed deployments and "
        "risking user-facing errors during every release cycle."
    ),
    technical_risk=(
        "Free, Shared, and Basic plan tiers do not support deployment slots, making "
        "blue-green and canary deployment patterns impossible and forcing in-place "
        "deployments with no automated rollback capability."
    ),
    azure_cli=(
        "# Upgrade the App Service plan to Standard tier\n"
        "az appservice plan update \\\n"
        "  --name <plan-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --sku S1\n\n"
        "# Create a staging deployment slot\n"
        "az webapp deployment slot create \\\n"
        "  --name <app-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --slot staging\n\n"
        "# Swap staging → production after validation\n"
        "az webapp deployment slot swap \\\n"
        "  --name <app-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --slot staging \\\n"
        "  --target-slot production"
    ),
    bicep=(
        "resource appPlan 'Microsoft.Web/serverfarms@2023-01-01' = {\n"
        "  name: planName\n"
        "  location: location\n"
        "  sku: { name: 'S1', tier: 'Standard', capacity: 1 }\n"
        "}\n\n"
        "resource stagingSlot 'Microsoft.Web/sites/slots@2023-01-01' = {\n"
        "  name: '${appName}/staging'\n"
        "  location: location\n"
        "  properties: {}\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_service_plan" "plan" {\n'
        "  name                = var.plan_name\n"
        "  resource_group_name = var.resource_group_name\n"
        "  location            = var.location\n"
        '  os_type             = "Linux"\n'
        '  sku_name            = "S1"\n'
        "}\n\n"
        'resource "azurerm_linux_web_app_slot" "staging" {\n'
        '  name           = "staging"\n'
        "  app_service_id = azurerm_linux_web_app.app.id\n"
        "}"
    ),
    estimated_effort="Medium (~2-4 hours including CI/CD pipeline update)",
    risk_reduction="High (50-70% deployment risk reduction via blue-green pattern)",
)

_register(
    "OPS-MON-001",
    business_impact=(
        "Without Application Insights, operations teams have no visibility into "
        "application errors, latency spikes, or dependency failures, leading to "
        "longer MTTR and undetected degradation impacting end-user experience."
    ),
    technical_risk=(
        "No application-layer telemetry means failed requests, slow dependencies, "
        "and exception rates are invisible until users report issues; distributed "
        "traces for root-cause analysis are unavailable."
    ),
    azure_cli=(
        "# Create Application Insights resource\n"
        "az monitor app-insights component create \\\n"
        "  --app <ai-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --location <location> \\\n"
        "  --kind web\n\n"
        "# Link to App Service via connection string\n"
        "az webapp config appsettings set \\\n"
        "  --name <app-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        '  --settings APPLICATIONINSIGHTS_CONNECTION_STRING="<connection-string>"'
    ),
    bicep=(
        "resource ai 'Microsoft.Insights/components@2020-02-02' = {\n"
        "  name: aiName\n"
        "  location: location\n"
        "  kind: 'web'\n"
        "  properties: { Application_Type: 'web' }\n"
        "}\n\n"
        "resource app 'Microsoft.Web/sites@2023-01-01' = {\n"
        "  properties: {\n"
        "    siteConfig: {\n"
        "      appSettings: [\n"
        "        {\n"
        "          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'\n"
        "          value: ai.properties.ConnectionString\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_application_insights" "ai" {\n'
        "  name                = var.ai_name\n"
        "  location            = var.location\n"
        "  resource_group_name = var.resource_group_name\n"
        '  application_type    = "web"\n'
        "}\n\n"
        'resource "azurerm_linux_web_app" "app" {\n'
        "  app_settings = {\n"
        '    "APPLICATIONINSIGHTS_CONNECTION_STRING" = azurerm_application_insights.ai.connection_string\n'
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~45 min)",
    risk_reduction="High (60-80% observability gap closure)",
)

# ===========================================================================
# PERFORMANCE EFFICIENCY
# ===========================================================================

_register(
    "PER-ALERT-001",
    business_impact=(
        "Metric alert rules without action groups fire silently; performance "
        "threshold breaches go unnoticed until users experience degradation, "
        "causing SLA violations and increased customer churn."
    ),
    technical_risk=(
        "Silent alerts defeat monitoring instrumentation; without notifications, "
        "SRE and on-call teams cannot respond to CPU saturation, memory pressure, "
        "or latency regressions before they escalate to full outages."
    ),
    azure_cli=(
        "# Create an action group with email notification\n"
        "az monitor action-group create \\\n"
        "  --name <ag-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --action email admin admin@example.com\n\n"
        "# Attach the action group to the alert rule\n"
        "az monitor metrics alert update \\\n"
        "  --name <alert-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --action <action-group-resource-id>"
    ),
    bicep=(
        "resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {\n"
        "  name: agName\n"
        "  location: 'global'\n"
        "  properties: {\n"
        "    groupShortName: 'OpsAlert'\n"
        "    enabled: true\n"
        "    emailReceivers: [\n"
        "      { name: 'Admin', emailAddress: 'admin@example.com', useCommonAlertSchema: true }\n"
        "    ]\n"
        "  }\n"
        "}\n\n"
        "resource alert 'Microsoft.Insights/metricAlerts@2018-03-01' = {\n"
        "  properties: {\n"
        "    actions: [ { actionGroupId: actionGroup.id } ]\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_monitor_action_group" "ag" {\n'
        "  name                = var.ag_name\n"
        "  resource_group_name = var.resource_group_name\n"
        '  short_name          = "OpsAlert"\n'
        "  email_receiver {\n"
        '    name          = "Admin"\n'
        '    email_address = "admin@example.com"\n'
        "  }\n"
        "}\n\n"
        'resource "azurerm_monitor_metric_alert" "alert" {\n'
        "  action {\n"
        "    action_group_id = azurerm_monitor_action_group.ag.id\n"
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~30 min per alert rule)",
    risk_reduction="Medium (40-60% MTTD improvement for performance threshold breaches)",
)

_register(
    "PER-ADV-001",
    business_impact=(
        "Unresolved Advisor performance recommendations indicate sub-optimal resource "
        "sizing, leading to latency degradation and poor user experience that reduces "
        "conversion rates and increases support costs."
    ),
    technical_risk=(
        "Resources running near capacity limits without the correct SKU or "
        "configuration exhibit unpredictable failure modes under load, risking "
        "cascading failures in dependent services."
    ),
    azure_cli=(
        "# List all open Advisor Performance recommendations\n"
        "az advisor recommendation list \\\n"
        "  --category Performance \\\n"
        "  --output table\n\n"
        "# Dismiss a recommendation once resolved\n"
        "az advisor recommendation disable \\\n"
        "  --recommendation-id <recommendation-id>"
    ),
    bicep=(
        "# Bicep remediation is recommendation-specific.\n"
        "# Review the Advisor recommendation details and update\n"
        "# the affected resource's SKU or configuration properties."
    ),
    terraform=(
        "# Terraform remediation is recommendation-specific.\n"
        "# Review the Advisor recommendation details and update\n"
        "# the affected resource block's SKU, tier, or capacity."
    ),
    estimated_effort="Medium (~2-8 hours, varies by recommendation type)",
    risk_reduction="Medium (20-50% performance improvement, varies by resource type)",
)

_register(
    "PER-LT-001",
    business_impact=(
        "Without load testing, production systems may fail under peak traffic, "
        "causing revenue loss, SLA breaches, and reputational damage during "
        "high-demand events such as product launches or seasonal peaks."
    ),
    technical_risk=(
        "Capacity limits, thread-pool exhaustion, database connection saturation, "
        "and dependency timeouts under concurrency are invisible until production "
        "traffic exceeds the untested threshold, causing live outages."
    ),
    azure_cli=(
        "# Create Azure Load Testing resource\n"
        "az load create \\\n"
        "  --name <lt-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --location <location>\n\n"
        "# Create and run a baseline test (requires a JMeter/Locust config file)\n"
        "az load test create \\\n"
        "  --load-test-resource <lt-name> \\\n"
        "  --resource-group <resource-group> \\\n"
        "  --test-id baseline-load-test \\\n"
        "  --load-test-config-file loadtest.yaml"
    ),
    bicep=(
        "resource loadTest 'Microsoft.LoadTestService/loadTests@2022-12-01' = {\n"
        "  name: ltName\n"
        "  location: location\n"
        "  properties: { description: 'Baseline load test configuration' }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_load_test" "lt" {\n'
        "  name                = var.lt_name\n"
        "  location            = var.location\n"
        "  resource_group_name = var.resource_group_name\n"
        "}"
    ),
    estimated_effort="High (~1-2 days to create test plan and establish baseline)",
    risk_reduction="High (70-90% reduction in surprise capacity failures under peak load)",
)

# ===========================================================================
# COST OPTIMIZATION
# ===========================================================================

_register(
    "CST-BUDGET-001",
    business_impact=(
        "Budgets without alert thresholds allow unchecked cloud spending to exceed "
        "approved limits, causing budget overruns, unexpected invoices, and potential "
        "project suspension pending financial review."
    ),
    technical_risk=(
        "Without spend alerts at 80% actual and 100% forecast thresholds, finance "
        "and engineering teams receive no early warning signal; corrective action is "
        "only possible after overspend has already occurred."
    ),
    azure_cli=(
        "# Add 80% actual-spend notification\n"
        "az consumption budget create \\\n"
        "  --budget-name <budget-name> \\\n"
        "  --amount <monthly-amount> \\\n"
        "  --time-grain Monthly \\\n"
        "  --start-date <YYYY-MM-01> \\\n"
        "  --end-date <YYYY-MM-01+1year> \\\n"
        "  --contact-emails admin@example.com \\\n"
        "  --threshold 80 \\\n"
        "  --threshold-type Actual\n\n"
        "# Add 100% forecast notification\n"
        "az consumption budget create \\\n"
        "  --budget-name <budget-name>-forecast \\\n"
        "  --threshold 100 \\\n"
        "  --threshold-type Forecasted"
    ),
    bicep=(
        "resource budget 'Microsoft.Consumption/budgets@2023-05-01' = {\n"
        "  name: budgetName\n"
        "  properties: {\n"
        "    amount: budgetAmount\n"
        "    timeGrain: 'Monthly'\n"
        "    notifications: {\n"
        "      actualAt80: {\n"
        "        enabled: true\n"
        "        operator: 'GreaterThan'\n"
        "        threshold: 80\n"
        "        contactEmails: [ 'admin@example.com' ]\n"
        "        thresholdType: 'Actual'\n"
        "      }\n"
        "      forecastAt100: {\n"
        "        enabled: true\n"
        "        operator: 'GreaterThan'\n"
        "        threshold: 100\n"
        "        contactEmails: [ 'admin@example.com' ]\n"
        "        thresholdType: 'Forecasted'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_consumption_budget_subscription" "budget" {\n'
        "  name            = var.budget_name\n"
        "  subscription_id = var.subscription_id\n"
        "  amount          = var.budget_amount\n"
        '  time_grain      = "Monthly"\n'
        "  time_period {\n"
        '    start_date = "2024-01-01T00:00:00Z"\n'
        "  }\n"
        "  notification {\n"
        "    enabled        = true\n"
        "    threshold      = 80\n"
        '    operator       = "GreaterThan"\n'
        '    threshold_type = "Actual"\n'
        '    contact_emails = ["admin@example.com"]\n'
        "  }\n"
        "  notification {\n"
        "    enabled        = true\n"
        "    threshold      = 100\n"
        '    operator       = "GreaterThan"\n'
        '    threshold_type = "Forecasted"\n'
        '    contact_emails = ["admin@example.com"]\n'
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~20 min)",
    risk_reduction="Medium (50-70% budget overrun prevention)",
)

_register(
    "CST-COST-TAG-001",
    business_impact=(
        "Resources without cost allocation tags cannot be attributed to business "
        "units, making it impossible to hold teams accountable for spending or to "
        "identify which products are driving unexpected Azure bills."
    ),
    technical_risk=(
        "Without mandatory tagging enforced via Azure Policy, tag drift continues "
        "as new resources are deployed, compounding the cost attribution problem and "
        "defeating chargeback / showback reporting over time."
    ),
    azure_cli=(
        "# Tag an individual resource\n"
        "az tag update \\\n"
        "  --resource-id <resource-id> \\\n"
        "  --operation Merge \\\n"
        '  --tags CostCenter=<code> Team=<team-name>\n\n'
        "# Enforce tagging at scale via Azure Policy (built-in 'Require a tag')\n"
        "az policy assignment create \\\n"
        "  --name RequireCostCenterTag \\\n"
        "  --policy 1e30110a-5ceb-460c-a204-c1c3969c6d62 \\\n"
        "  --scope /subscriptions/<subscription-id> \\\n"
        "  --params '{\"tagName\": {\"value\": \"CostCenter\"}}'"
    ),
    bicep=(
        "resource anyResource 'Microsoft.Web/sites@2023-01-01' = {\n"
        "  name: resourceName\n"
        "  location: location\n"
        "  tags: {\n"
        "    CostCenter: costCenterCode\n"
        "    Team: teamName\n"
        "    Environment: environment\n"
        "  }\n"
        "}"
    ),
    terraform=(
        'resource "azurerm_linux_web_app" "app" {\n'
        "  # ... other configuration ...\n"
        "  tags = {\n"
        "    CostCenter  = var.cost_center\n"
        "    Team        = var.team_name\n"
        "    Environment = var.environment\n"
        "  }\n"
        "}"
    ),
    estimated_effort="Low (~15 min per resource; use Policy for at-scale enforcement)",
    risk_reduction="Medium (40-60% cost attribution and chargeback accuracy improvement)",
)

_register(
    "CST-ADV-001",
    business_impact=(
        "Unresolved Advisor cost recommendations represent direct, quantified monthly "
        "savings being left unrealised, increasing Azure spend beyond workload "
        "requirements and reducing budget available for strategic initiatives."
    ),
    technical_risk=(
        "Over-provisioned resources may mask real capacity and scaling constraints; "
        "right-sizing improves both cost predictability and performance headroom."
    ),
    azure_cli=(
        "# List all open Advisor Cost recommendations\n"
        "az advisor recommendation list \\\n"
        "  --category Cost \\\n"
        "  --output table\n\n"
        "# Show details of a specific recommendation\n"
        "az advisor recommendation show \\\n"
        "  --recommendation-id <recommendation-id>"
    ),
    bicep=(
        "# Bicep remediation is recommendation-specific.\n"
        "# Review Advisor cost recommendation details and adjust\n"
        "# the affected resource's SKU, tier, or retention settings."
    ),
    terraform=(
        "# Terraform remediation is recommendation-specific.\n"
        "# Review Advisor cost recommendation details and update\n"
        "# the affected resource's SKU, tier, or capacity arguments."
    ),
    estimated_effort="Low-Medium (~30 min to several hours per recommendation)",
    risk_reduction="Medium-High (10-40% cost reduction, varies by recommendation type)",
)


# ===========================================================================
# Fallback tables — pillar and severity derived
# ===========================================================================

_PILLAR_BUSINESS_IMPACT: dict[str, str] = {
    "security": (
        "Security misconfigurations create active attack vectors that can lead to "
        "data breaches, compliance failures (PCI-DSS, ISO 27001, SOC 2), and "
        "significant reputational and financial consequences."
    ),
    "reliability": (
        "Reliability gaps increase the probability of service outages, SLA breaches, "
        "and revenue loss during failure scenarios or high-traffic periods."
    ),
    "operational_excellence": (
        "Operational gaps extend mean-time-to-recover, reduce deployment confidence, "
        "and increase engineering toil and incident response costs."
    ),
    "performance_efficiency": (
        "Performance inefficiencies degrade end-user experience, increase response "
        "latency, and can cause cascading failures in dependent services under load."
    ),
    "cost_optimization": (
        "Cost inefficiencies increase Azure spend beyond workload requirements, "
        "reducing budget available for product development and strategic initiatives."
    ),
}

_SEVERITY_TECHNICAL_RISK: dict[str, str] = {
    "critical": (
        "Critical severity — immediate, actively exploitable risk with high "
        "likelihood of breach or outage if not addressed within 24 hours."
    ),
    "high": (
        "High severity — significantly increases attack surface or failure "
        "probability; exploitation or failure is feasible without specialist "
        "knowledge and should be resolved within 7 days."
    ),
    "medium": (
        "Medium severity — meaningful risk that, combined with other factors, "
        "could contribute to a security or reliability incident; resolve within 30 days."
    ),
    "low": (
        "Low severity — configuration hygiene or best-practice gap with limited "
        "direct exploitability; resolve within the next sprint or quarter."
    ),
    "informational": (
        "Informational — best-practice observation with negligible direct risk; "
        "track for compliance reporting and address opportunistically."
    ),
}

_SEVERITY_EFFORT: dict[str, str] = {
    "critical":      "Medium (~2-4 hours — urgent, prioritise immediately)",
    "high":          "Medium (~1-3 hours)",
    "medium":        "Low-Medium (~30 min to 2 hours)",
    "low":           "Low (~15-30 min)",
    "informational": "Minimal (~15 min)",
}

_SEVERITY_RISK_REDUCTION: dict[str, str] = {
    "critical":      "High (60-90% risk reduction upon remediation)",
    "high":          "High (40-70% risk reduction upon remediation)",
    "medium":        "Medium (20-40% risk reduction upon remediation)",
    "low":           "Low-Medium (10-25% risk reduction upon remediation)",
    "informational": "Low (5-10% compliance score improvement)",
}


# ===========================================================================
# Public API
# ===========================================================================

def get_remediation_detail(
    rule_id: str,
    *,
    severity: str,
    pillar: str,
    resource_type: str,
    recommendation: str,
) -> RemediationDetail:
    """Return the RemediationDetail for rule_id with graceful fallback.

    Args:
        rule_id:       The finding's rule_id (e.g. "SEC-CR-001").
        severity:      Finding severity value string (e.g. "critical").
        pillar:        WAF pillar key (e.g. "security").
        resource_type: ARM resource type (e.g. "microsoft.web/sites").
        recommendation: Existing recommendation text used as CLI fallback.

    Returns:
        Populated RemediationDetail — never None, never raises.
    """
    if rule_id in _TEMPLATES:
        return _TEMPLATES[rule_id]

    return RemediationDetail(
        business_impact=_PILLAR_BUSINESS_IMPACT.get(
            pillar,
            "This finding may affect business operations, compliance posture, or "
            "costs. Review the finding details for the specific organisational impact.",
        ),
        technical_risk=_SEVERITY_TECHNICAL_RISK.get(
            severity,
            "Review the finding evidence and recommendation for technical risk details.",
        ),
        azure_cli=recommendation,
        bicep=(
            "# Update the Bicep resource block to address this finding.\n"
            "# See the Azure Bicep documentation for the resource type:\n"
            f"# {resource_type}\n"
            "# Apply the recommended configuration to the 'properties' block."
        ),
        terraform=(
            "# Update the Terraform resource block to address this finding.\n"
            "# See the azurerm provider documentation for the resource type:\n"
            f"# {resource_type}\n"
            "# Apply the recommended configuration change to the resource arguments."
        ),
        estimated_effort=_SEVERITY_EFFORT.get(severity, "Medium (~1-2 hours)"),
        risk_reduction=_SEVERITY_RISK_REDUCTION.get(
            severity, "Medium (20-50% risk reduction upon remediation)"
        ),
    )
