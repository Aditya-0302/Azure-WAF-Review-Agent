variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_pe_id" { type = string }
variable "vnet_id" { type = string }
variable "log_analytics_workspace_id" { type = string }
variable "tags" { type = map(string) }

data "azurerm_client_config" "current" {}

# ── Key Vault (Premium — HSM-backed keys) ────────────────────────────────────

resource "azurerm_key_vault" "main" {
  name                        = "kv-${var.prefix}"
  location                    = var.location
  resource_group_name         = var.resource_group_name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium"
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true
  enable_rbac_authorization   = true

  network_acls {
    bypass                     = "AzureServices"
    default_action             = "Deny"
    virtual_network_subnet_ids = []
    ip_rules                   = []
  }

  tags = var.tags
}

# ── Private endpoint for Key Vault ────────────────────────────────────────────

resource "azurerm_private_endpoint" "key_vault" {
  name                = "pe-${var.prefix}-kv"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-kv"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "pdns-kv"
    private_dns_zone_ids = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${var.resource_group_name}/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"]
  }
}

# ── Diagnostic setting — audit all Key Vault operations ───────────────────────

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diag-kv"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "AuditEvent" }
  enabled_log { category = "AzurePolicyEvaluationDetails" }
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "key_vault_id"  { value = azurerm_key_vault.main.id }
output "key_vault_uri" { value = azurerm_key_vault.main.vault_uri }
output "key_vault_name" { value = azurerm_key_vault.main.name }
