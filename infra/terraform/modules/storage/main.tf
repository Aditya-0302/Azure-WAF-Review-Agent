variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "location_secondary" { type = string }
variable "subnet_pe_id" { type = string }
variable "vnet_id" { type = string }
variable "tags" { type = map(string) }

# ── Container Registry (Premium — geo-replication + private endpoint) ─────────

resource "azurerm_container_registry" "main" {
  name                          = "${replace(var.prefix, "-", "")}acr"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  zone_redundancy_enabled       = true
  tags                          = var.tags

  georeplications {
    location                  = var.location_secondary
    zone_redundancy_enabled   = true
    regional_endpoint_enabled = true
    tags                      = var.tags
  }
}

resource "azurerm_private_endpoint" "acr" {
  name                = "pe-${var.prefix}-acr"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-acr"
    private_connection_resource_id = azurerm_container_registry.main.id
    subresource_names              = ["registry"]
    is_manual_connection           = false
  }
}

# ── Blob Storage — WAF reports (ZRS in primary region) ───────────────────────

resource "azurerm_storage_account" "reports" {
  name                          = "${replace(var.prefix, "-", "")}reports"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  account_tier                  = "Standard"
  account_replication_type      = "ZRS"
  account_kind                  = "StorageV2"
  min_tls_version               = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled = false
  enable_https_traffic_only     = true
  shared_access_key_enabled     = true  # SAS token generation requires this.
  tags                          = var.tags

  blob_properties {
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "reports" {
  name                  = "waf-reports"
  storage_account_name  = azurerm_storage_account.reports.name
  container_access_type = "private"
}

# ── Lifecycle management — expire reports after 90 days ──────────────────────

resource "azurerm_storage_management_policy" "reports" {
  storage_account_id = azurerm_storage_account.reports.id

  rule {
    name    = "expire-old-reports"
    enabled = true

    filters {
      prefix_match = ["waf-reports/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 30
        tier_to_archive_after_days_since_modification_greater_than = 60
        delete_after_days_since_modification_greater_than          = 90
      }
      snapshot {
        delete_after_days_since_creation_greater_than = 30
      }
    }
  }
}

resource "azurerm_private_endpoint" "storage" {
  name                = "pe-${var.prefix}-storage"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-storage"
    private_connection_resource_id = azurerm_storage_account.reports.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "acr_id"                       { value = azurerm_container_registry.main.id }
output "acr_login_server"             { value = azurerm_container_registry.main.login_server }
output "storage_account_id"           { value = azurerm_storage_account.reports.id }
output "storage_account_blob_endpoint" { value = azurerm_storage_account.reports.primary_blob_endpoint }
output "storage_account_name"         { value = azurerm_storage_account.reports.name }
