variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_pe_id" { type = string }
variable "vnet_id" { type = string }
variable "openai_gpt4o_capacity" { type = number }
variable "search_sku" { type = string }
variable "search_replica_count" { type = number }
variable "key_vault_id" { type = string }
variable "tags" { type = map(string) }

# ── Azure OpenAI ──────────────────────────────────────────────────────────────

resource "azurerm_cognitive_account" "openai" {
  name                          = "oai-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  kind                          = "OpenAI"
  sku_name                      = "S0"
  public_network_access_enabled = false
  local_auth_enabled            = false  # Workload Identity only.
  custom_subdomain_name         = "oai-${var.prefix}"
  tags                          = var.tags
}

resource "azurerm_cognitive_deployment" "gpt4o" {
  name                 = "gpt-4o"
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = "gpt-4o"
    version = "2024-08-06"
  }

  scale {
    type     = "Standard"
    capacity = var.openai_gpt4o_capacity
  }
}

resource "azurerm_private_endpoint" "openai" {
  name                = "pe-${var.prefix}-oai"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-oai"
    private_connection_resource_id = azurerm_cognitive_account.openai.id
    subresource_names              = ["account"]
    is_manual_connection           = false
  }
}

# ── Azure AI Search ───────────────────────────────────────────────────────────

resource "azurerm_search_service" "main" {
  name                          = "srch-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  sku                           = var.search_sku
  replica_count                 = var.search_replica_count
  partition_count               = 1
  public_network_access_enabled = false
  local_authentication_enabled  = false  # RBAC only.
  tags                          = var.tags
}

resource "azurerm_private_endpoint" "search" {
  name                = "pe-${var.prefix}-search"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-search"
    private_connection_resource_id = azurerm_search_service.main.id
    subresource_names              = ["searchService"]
    is_manual_connection           = false
  }
}

# ── Store endpoints in Key Vault for CSI driver consumption ───────────────────

resource "azurerm_key_vault_secret" "openai_endpoint" {
  name         = "azure-openai-endpoint"
  value        = azurerm_cognitive_account.openai.endpoint
  key_vault_id = var.key_vault_id

  depends_on = [azurerm_cognitive_account.openai]
}

resource "azurerm_key_vault_secret" "search_endpoint" {
  name         = "azure-search-endpoint"
  value        = "https://${azurerm_search_service.main.name}.search.windows.net"
  key_vault_id = var.key_vault_id

  depends_on = [azurerm_search_service.main]
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "openai_id"       { value = azurerm_cognitive_account.openai.id }
output "openai_endpoint" { value = azurerm_cognitive_account.openai.endpoint }
output "search_id"       { value = azurerm_search_service.main.id }
output "search_endpoint" { value = "https://${azurerm_search_service.main.name}.search.windows.net" }
