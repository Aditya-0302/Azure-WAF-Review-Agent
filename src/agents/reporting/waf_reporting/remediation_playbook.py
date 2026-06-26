"""Remediation playbooks — step-by-step implementation guidance per WAF rule.

For each known WAF rule, provides:
  1. Portal Steps  — Azure Portal navigation sequence
  2. Azure CLI     — az commands (sourced from remediation_templates)
  3. PowerShell    — Az module / Invoke-AzRestMethod commands
  4. Bicep         — resource snippet (sourced from remediation_templates)
  5. Terraform     — azurerm provider block (sourced from remediation_templates)

Only rules registered in _PORTAL_PS have a playbook.  Unknown rules return
None and the caller displays "Manual remediation guidance required."

Architecture:
  - Add new playbooks by calling _register() with the rule_id and 3 kwargs.
  - CLI, Bicep, Terraform are read live from remediation_templates so they
    stay in sync without duplication.
  - Never raises: all public functions are fully defensive.
"""

from __future__ import annotations

from dataclasses import dataclass

from waf_shared.domain.models.finding import Finding
from waf_reporting.remediation_templates import get_remediation_detail


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PlaybookEntry:
    """Complete remediation playbook for one finding / rule."""

    portal_steps: str
    azure_cli: str
    powershell: str
    bicep: str
    terraform: str
    change_type: str  # simple_config | policy | network | architecture


@dataclass(frozen=True)
class _PortalPSEntry:
    portal_steps: str
    powershell: str
    change_type: str  # simple_config | policy | network | architecture


# ── Lookup tables ──────────────────────────────────────────────────────────────

_PORTAL_PS: dict[str, _PortalPSEntry] = {}

_CHANGE_TYPE_FIX_TIME: dict[str, str] = {
    "simple_config": "15 minutes",
    "policy": "30 minutes",
    "network": "60 minutes",
    "architecture": "2–4 hours",
}

_SEVERITY_FIX_TIME_FALLBACK: dict[str, str] = {
    "critical": "2–4 hours",
    "high": "60 minutes",
    "medium": "30 minutes",
    "low": "15 minutes",
    "informational": "15 minutes",
}

_SEVERITY_RISK_REDUCTION: dict[str, str] = {
    "critical": "High",
    "high": "Medium",
    "medium": "Medium",
    "low": "Low",
    "informational": "Low",
}


def _register(rule_id: str, portal_steps: str, powershell: str, change_type: str) -> None:
    _PORTAL_PS[rule_id] = _PortalPSEntry(
        portal_steps=portal_steps,
        powershell=powershell,
        change_type=change_type,
    )


# ===========================================================================
# SECURITY
# ===========================================================================

# ── SEC-CR-001 — Container Registry content trust ─────────────────────────

_register(
    "SEC-CR-001",
    portal_steps=(
        "1. Azure Portal → Container Registries → [your registry]\n"
        "2. Security → Trust Policy\n"
        "3. Set Status to Enabled\n"
        "4. Click Save"
    ),
    powershell=(
        "# No native Az module cmdlet — use Invoke-AzRestMethod\n"
        "$body = '{\"properties\":{\"policies\":{\"trustPolicy\":{\"status\":\"enabled\",\"type\":\"Notary\"}}}}'\n"
        "Invoke-AzRestMethod `\n"
        "  -Path \"/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/<registry>?api-version=2023-07-01\" `\n"
        "  -Method PATCH `\n"
        "  -Payload $body"
    ),
    change_type="simple_config",
)

# ── SEC-DEF-001 — Microsoft Defender for Cloud ─────────────────────────────

_register(
    "SEC-DEF-001",
    portal_steps=(
        "1. Azure Portal → Microsoft Defender for Cloud\n"
        "2. Environment Settings → [your subscription]\n"
        "3. Defender Plans → Enable the required plan(s)\n"
        "4. Click Save"
    ),
    powershell=(
        "# Enable Defender Standard for each workload type\n"
        "Set-AzSecurityPricing -Name 'Containers'      -PricingTier 'Standard'\n"
        "Set-AzSecurityPricing -Name 'VirtualMachines' -PricingTier 'Standard'\n"
        "Set-AzSecurityPricing -Name 'SqlServers'      -PricingTier 'Standard'\n"
        "Set-AzSecurityPricing -Name 'Storage'         -PricingTier 'Standard'\n"
        "Set-AzSecurityPricing -Name 'AppServices'     -PricingTier 'Standard'\n"
        "Set-AzSecurityPricing -Name 'KeyVaults'       -PricingTier 'Standard'"
    ),
    change_type="simple_config",
)

# ── SEC-NET-004 — App Service VNet Integration ──────────────────────────────

_register(
    "SEC-NET-004",
    portal_steps=(
        "1. Azure Portal → App Services → [your app]\n"
        "2. Settings → Networking → VNet Integration\n"
        "3. Add VNet Integration → select Virtual Network and subnet\n"
        "4. Enable Route All to route all outbound traffic through VNet\n"
        "5. Click OK"
    ),
    powershell=(
        "# Add VNet integration via REST API (no native Az module cmdlet)\n"
        "$body = ConvertTo-Json @{ properties = @{ vnetResourceId = '<subnet-resource-id>'; isSwift = $true } }\n"
        "Invoke-AzRestMethod `\n"
        "  -Path \"/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Web/sites/<app>/networkConfig/virtualNetwork?api-version=2023-01-01\" `\n"
        "  -Method PUT -Payload $body\n\n"
        "# Enable route-all outbound traffic through VNet\n"
        "Set-AzWebApp -Name '<app-name>' -ResourceGroupName '<rg>' `\n"
        "  -AppSettings @{ 'WEBSITE_VNET_ROUTE_ALL' = '1' }"
    ),
    change_type="network",
)

# ===========================================================================
# RELIABILITY
# ===========================================================================

# ── REL-AGW-002 — Application Gateway custom health probes ─────────────────

_register(
    "REL-AGW-002",
    portal_steps=(
        "1. Azure Portal → Application Gateways → [your gateway]\n"
        "2. Settings → Health Probes → Add\n"
        "3. Protocol: HTTP | Path: /health | Interval: 30 | Timeout: 30 | Threshold: 3\n"
        "4. Pick hostname from backend HTTP settings\n"
        "5. Associate probe with each backend HTTP setting → Save"
    ),
    powershell=(
        "$agw = Get-AzApplicationGateway -Name '<gateway-name>' -ResourceGroupName '<rg>'\n"
        "Add-AzApplicationGatewayProbeConfig -ApplicationGateway $agw `\n"
        "  -Name 'AppHealthProbe' `\n"
        "  -Protocol Http `\n"
        "  -HostNameFromHttpSettings `\n"
        "  -Path '/health' `\n"
        "  -Interval 30 `\n"
        "  -Timeout 30 `\n"
        "  -UnhealthyThreshold 3\n"
        "Set-AzApplicationGateway -ApplicationGateway $agw"
    ),
    change_type="network",
)

# ── REL-SB-001 — Service Bus namespace tier upgrade ────────────────────────

_register(
    "REL-SB-001",
    portal_steps=(
        "1. Azure Portal → Service Bus Namespaces → [your namespace]\n"
        "2. Settings → Pricing Tier\n"
        "3. Select Standard (or Premium for zone redundancy)\n"
        "4. Click Apply"
    ),
    powershell=(
        "Set-AzServiceBusNamespace `\n"
        "  -ResourceGroupName '<rg>' `\n"
        "  -Name '<namespace-name>' `\n"
        "  -SkuName 'Standard'\n\n"
        "# For mission-critical workloads — upgrade to Premium with zone redundancy:\n"
        "# Set-AzServiceBusNamespace -ResourceGroupName '<rg>' -Name '<namespace-name>' `\n"
        "#   -SkuName 'Premium' -ZoneRedundant"
    ),
    change_type="architecture",
)

# ── REL-ASR-001 — Recovery Services cross-region restore ───────────────────

_register(
    "REL-ASR-001",
    portal_steps=(
        "1. Azure Portal → Recovery Services Vaults → [your vault]\n"
        "2. Settings → Properties → Backup Configuration → Update\n"
        "3. Storage Replication Type: Geo-Redundant\n"
        "4. Enable Cross Region Restore\n"
        "5. Click Save"
    ),
    powershell=(
        "$vault = Get-AzRecoveryServicesVault -Name '<vault-name>' -ResourceGroupName '<rg>'\n"
        "Set-AzRecoveryServicesBackupProperty -Vault $vault `\n"
        "  -BackupStorageRedundancy GeoRedundant\n\n"
        "# Enable cross-region restore\n"
        "Set-AzRecoveryServicesVaultProperty `\n"
        "  -VaultId $vault.ID `\n"
        "  -CrossRegionRestore $true"
    ),
    change_type="simple_config",
)

# ===========================================================================
# OPERATIONAL EXCELLENCE
# ===========================================================================

# ── OPS-DIAG-001 — VM boot diagnostics ─────────────────────────────────────

_register(
    "OPS-DIAG-001",
    portal_steps=(
        "1. Azure Portal → Virtual Machines → [your VM]\n"
        "2. Help → Boot Diagnostics → Enable\n"
        "3. Select Managed Storage Account (recommended)\n"
        "4. Click Apply"
    ),
    powershell=(
        "$vm = Get-AzVM -Name '<vm-name>' -ResourceGroupName '<rg>'\n"
        "Set-AzVMBootDiagnostic -VM $vm -Enable\n"
        "Update-AzVM -VM $vm -ResourceGroupName '<rg>'"
    ),
    change_type="simple_config",
)

# ── OPS-SLOT-001 — App Service deployment slots ─────────────────────────────

_register(
    "OPS-SLOT-001",
    portal_steps=(
        "1. Azure Portal → App Services → [your app]\n"
        "2. If needed: App Service Plan → Scale Up → Standard S1 or higher\n"
        "3. Deployment → Deployment Slots → Add Slot → Name: staging → Add\n"
        "4. Deploy to staging, validate, then Swap → production"
    ),
    powershell=(
        "# Upgrade App Service Plan to Standard tier (required for slots)\n"
        "Set-AzAppServicePlan -Name '<plan-name>' -ResourceGroupName '<rg>' `\n"
        "  -Tier 'Standard' -WorkerSize 'Small'\n\n"
        "# Create staging deployment slot\n"
        "New-AzWebAppSlot -Name '<app-name>' -ResourceGroupName '<rg>' -Slot 'staging'\n\n"
        "# Swap staging → production after validation\n"
        "Switch-AzWebAppSlot -SourceSlotName 'staging' `\n"
        "  -Name '<app-name>' -ResourceGroupName '<rg>'"
    ),
    change_type="architecture",
)

# ── OPS-MON-001 — Application Insights integration ─────────────────────────

_register(
    "OPS-MON-001",
    portal_steps=(
        "1. Azure Portal → App Services → [your app]\n"
        "2. Settings → Application Insights → Turn on Application Insights\n"
        "3. Select or create an Application Insights resource\n"
        "4. Click Apply → Yes to restart the app"
    ),
    powershell=(
        "# Create Application Insights resource\n"
        "$ai = New-AzApplicationInsights -Name '<ai-name>' `\n"
        "  -ResourceGroupName '<rg>' -Location '<location>' -Kind 'web'\n\n"
        "# Connect App Service via connection string\n"
        "Set-AzWebApp -Name '<app-name>' -ResourceGroupName '<rg>' `\n"
        "  -AppSettings @{ 'APPLICATIONINSIGHTS_CONNECTION_STRING' = $ai.ConnectionString }"
    ),
    change_type="architecture",
)

# ===========================================================================
# PERFORMANCE EFFICIENCY
# ===========================================================================

# ── PER-ALERT-001 — Metric alert action groups ──────────────────────────────

_register(
    "PER-ALERT-001",
    portal_steps=(
        "1. Azure Portal → Monitor → Alerts → Action Groups → Create\n"
        "2. Configure email/SMS notifications for on-call recipients → Create\n"
        "3. Alert Rules → [affected alert] → Edit\n"
        "4. Action Groups → Add → select the new action group\n"
        "5. Click Save"
    ),
    powershell=(
        "# Create action group with email notification\n"
        "$ag = New-AzActionGroup -Name '<ag-name>' -ResourceGroupName '<rg>' `\n"
        "  -ShortName 'OpsAlert' `\n"
        "  -EmailReceiver @{ Name='Admin'; EmailAddress='admin@example.com'; UseCommonAlertSchema=$true }\n\n"
        "# Associate action group with the metric alert rule\n"
        "Update-AzMetricAlertRuleV2 -Name '<alert-name>' -ResourceGroupName '<rg>' `\n"
        "  -ActionGroupId $ag.Id"
    ),
    change_type="simple_config",
)

# ── PER-ADV-001 — Advisor Performance recommendations ──────────────────────

_register(
    "PER-ADV-001",
    portal_steps=(
        "1. Azure Portal → Azure Advisor → Performance\n"
        "2. Review each recommendation — click for full details\n"
        "3. Click Remediate (if available) or follow the linked action\n"
        "4. Dismiss or Postpone once actioned"
    ),
    powershell=(
        "# List all Advisor Performance recommendations\n"
        "Get-AzAdvisorRecommendation -Category 'Performance' | `\n"
        "  Format-Table Category, Impact, ImpactedValue, ShortDescription -AutoSize"
    ),
    change_type="architecture",
)

# ── PER-LT-001 — Azure Load Testing ────────────────────────────────────────

_register(
    "PER-LT-001",
    portal_steps=(
        "1. Azure Portal → Create a resource → Azure Load Testing\n"
        "2. Select resource group, region, and name → Review + Create → Create\n"
        "3. Upload a JMeter or URL-based test plan\n"
        "4. Configure virtual users, duration, and ramp-up parameters\n"
        "5. Run the test and review results in the Load Test Dashboard"
    ),
    powershell=(
        "# Create Azure Load Testing resource via REST API\n"
        "# (No native Az module cmdlet available for this resource type)\n"
        "$body = ConvertTo-Json @{ location = '<location>'; properties = @{ description = 'Baseline load test' } }\n"
        "Invoke-AzRestMethod `\n"
        "  -Path \"/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.LoadTestService/loadTests/<name>?api-version=2022-12-01\" `\n"
        "  -Method PUT -Payload $body"
    ),
    change_type="architecture",
)

# ===========================================================================
# COST OPTIMIZATION
# ===========================================================================

# ── CST-BUDGET-001 — Budget alert thresholds ───────────────────────────────

_register(
    "CST-BUDGET-001",
    portal_steps=(
        "1. Azure Portal → Cost Management + Billing → Budgets → Add\n"
        "2. Set budget amount and monthly time period\n"
        "3. Alert Conditions → Add:\n"
        "   - Actual spend at 80% → email notification\n"
        "   - Forecasted spend at 100% → email notification\n"
        "4. Configure email recipients for each alert → Create"
    ),
    powershell=(
        "# Create budget with dual thresholds via REST API\n"
        "$body = ConvertTo-Json -Depth 10 @{\n"
        "  properties = @{\n"
        "    amount    = <monthly-amount>\n"
        "    timeGrain = 'Monthly'\n"
        "    timePeriod  = @{ startDate = '2024-01-01T00:00:00Z' }\n"
        "    category    = 'Cost'\n"
        "    notifications = @{\n"
        "      actual80    = @{ enabled=$true; operator='GreaterThan'; threshold=80; thresholdType='Actual'; contactEmails=@('admin@example.com') }\n"
        "      forecast100 = @{ enabled=$true; operator='GreaterThan'; threshold=100; thresholdType='Forecasted'; contactEmails=@('admin@example.com') }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "Invoke-AzRestMethod `\n"
        "  -Path \"/subscriptions/<sub-id>/providers/Microsoft.Consumption/budgets/<budget-name>?api-version=2023-05-01\" `\n"
        "  -Method PUT -Payload $body"
    ),
    change_type="simple_config",
)

# ── CST-COST-TAG-001 — Resource cost allocation tagging ─────────────────────

_register(
    "CST-COST-TAG-001",
    portal_steps=(
        "1. Azure Portal → select the affected resource → Overview → Tags\n"
        "2. Add required tags: CostCenter, Team, Environment → Apply\n"
        "For at-scale enforcement:\n"
        "3. Azure Policy → Definitions → Require a tag → Assign Policy"
    ),
    powershell=(
        "# Tag a specific resource\n"
        "Update-AzTag -ResourceId '<resource-id>' -Operation Merge `\n"
        "  -Tag @{ CostCenter = '<code>'; Team = '<team>'; Environment = '<env>' }\n\n"
        "# Enforce tagging at scale via Azure Policy\n"
        "New-AzPolicyAssignment -Name 'RequireCostCenterTag' `\n"
        "  -PolicyDefinition (Get-AzPolicyDefinition -Id '/providers/Microsoft.Authorization/policyDefinitions/1e30110a-5ceb-460c-a204-c1c3969c6d62') `\n"
        "  -Scope '/subscriptions/<subscription-id>' `\n"
        "  -PolicyParameterObject @{ tagName = @{ value = 'CostCenter' } }"
    ),
    change_type="policy",
)

# ── CST-ADV-001 — Advisor Cost recommendations ──────────────────────────────

_register(
    "CST-ADV-001",
    portal_steps=(
        "1. Azure Portal → Azure Advisor → Cost\n"
        "2. Review each recommendation — click for full details\n"
        "3. Click Remediate (if available) or follow the linked action\n"
        "4. Dismiss or Postpone once actioned"
    ),
    powershell=(
        "# List all Advisor Cost recommendations\n"
        "Get-AzAdvisorRecommendation -Category 'Cost' | `\n"
        "  Format-Table Category, Impact, ImpactedValue, ShortDescription -AutoSize\n\n"
        "# Get details for a specific impacted resource\n"
        "Get-AzAdvisorRecommendation -Category 'Cost' | `\n"
        "  Where-Object { $_.ImpactedValue -eq '<resource-name>' }"
    ),
    change_type="architecture",
)


# ── Public API ─────────────────────────────────────────────────────────────────

def build_remediation_playbook(finding: Finding) -> PlaybookEntry | None:
    """Return a PlaybookEntry for the finding's rule_id, or None if no playbook exists.

    CLI, Bicep, and Terraform are sourced from remediation_templates to avoid
    duplication.  Returns None for unknown rule_ids — callers should display
    "Manual remediation guidance required."  Never raises.
    """
    try:
        pps = _PORTAL_PS.get(finding.rule_id)
        if pps is None:
            return None
        detail = get_remediation_detail(
            finding.rule_id,
            severity=finding.severity.value,
            pillar=finding.pillar,
            resource_type=finding.resource_type,
            recommendation=finding.recommendation,
        )
        return PlaybookEntry(
            portal_steps=pps.portal_steps,
            azure_cli=detail.azure_cli,
            powershell=pps.powershell,
            bicep=detail.bicep,
            terraform=detail.terraform,
            change_type=pps.change_type,
        )
    except Exception:
        return None


def estimate_fix_time(finding: Finding) -> str:
    """Return the estimated fix time for the finding.

    Known rules: change_type → fix time (simple_config=15 min, policy=30 min,
    network=60 min, architecture=2–4 hours).
    Unknown rules: severity-based fallback.  Never raises.
    """
    try:
        pps = _PORTAL_PS.get(finding.rule_id)
        if pps is not None:
            return _CHANGE_TYPE_FIX_TIME.get(pps.change_type, "30 minutes")
        return _SEVERITY_FIX_TIME_FALLBACK.get(finding.severity.value, "30 minutes")
    except Exception:
        return "30 minutes"


def expected_risk_reduction(finding: Finding) -> str:
    """Return expected risk reduction label based on finding severity.

    Critical → High  |  High → Medium  |  Medium → Medium
    Low → Low  |  Informational → Low
    Never raises.
    """
    try:
        return _SEVERITY_RISK_REDUCTION.get(finding.severity.value, "Low")
    except Exception:
        return "Low"
