variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_postgres_id" { type = string }
variable "subnet_pe_id" { type = string }
variable "vnet_id" { type = string }
variable "postgres_sku" { type = string }
variable "postgres_storage_mb" { type = number }
variable "backup_retention_days" { type = number }
variable "admin_password" {
  type      = string
  sensitive = true
}
variable "log_analytics_workspace_id" { type = string }
variable "tags" { type = map(string) }

# ── Private DNS zone for PostgreSQL ──────────────────────────────────────────

resource "azurerm_private_dns_zone" "postgres" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "pdns-link-postgres"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = var.vnet_id
  registration_enabled  = false
}

# ── PostgreSQL Flexible Server (zone-redundant HA) ────────────────────────────

resource "azurerm_postgresql_flexible_server" "main" {
  name                          = "psql-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  version                       = "16"
  administrator_login           = "wafagent_admin"
  administrator_password        = var.admin_password
  storage_mb                    = var.postgres_storage_mb
  sku_name                      = var.postgres_sku
  backup_retention_days         = var.backup_retention_days
  geo_redundant_backup_enabled  = true
  delegated_subnet_id           = var.subnet_postgres_id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  zone                          = "1"

  high_availability {
    mode                      = "ZoneRedundant"
    standby_availability_zone = "2"
  }

  maintenance_window {
    day_of_week  = 0   # Sunday
    start_hour   = 2
    start_minute = 0
  }

  tags = var.tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

# ── Databases ─────────────────────────────────────────────────────────────────

resource "azurerm_postgresql_flexible_server_database" "wafagent" {
  name      = "wafagent"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# ── PostgreSQL server configuration ──────────────────────────────────────────

resource "azurerm_postgresql_flexible_server_configuration" "pgaudit_log" {
  name      = "pgaudit.log"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "DDL,WRITE"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_checkpoints" {
  name      = "log_checkpoints"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_connections" {
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_configuration" "ssl_enforce" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "on"
}

# ── PostgreSQL diagnostics → Log Analytics ────────────────────────────────────

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = "diag-postgres"
  target_resource_id         = azurerm_postgresql_flexible_server.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "PostgreSQLLogs" }
  metric { category = "AllMetrics" enabled = true }
}

# ── Redis Cache (zone-redundant, Standard C2) ─────────────────────────────────

resource "azurerm_redis_cache" "main" {
  name                          = "redis-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  capacity                      = 2
  family                        = "C"
  sku_name                      = "Standard"
  enable_non_ssl_port           = false
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
  tags                          = var.tags

  redis_configuration {
    maxmemory_policy = "allkeys-lru"
    maxmemory_reserved = 50
    maxfragmentationmemory_reserved = 50
  }
}

resource "azurerm_private_endpoint" "redis" {
  name                = "pe-${var.prefix}-redis"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-redis"
    private_connection_resource_id = azurerm_redis_cache.main.id
    subresource_names              = ["redisCache"]
    is_manual_connection           = false
  }
}

resource "azurerm_monitor_diagnostic_setting" "redis" {
  name                       = "diag-redis"
  target_resource_id         = azurerm_redis_cache.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "ConnectedClientList" }
  metric { category = "AllMetrics" enabled = true }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "postgres_fqdn"     { value = azurerm_postgresql_flexible_server.main.fqdn sensitive = true }
output "postgres_server_id" { value = azurerm_postgresql_flexible_server.main.id }
output "redis_hostname"    { value = azurerm_redis_cache.main.hostname sensitive = true }
output "redis_port"        { value = azurerm_redis_cache.main.ssl_port }
output "redis_primary_key" { value = azurerm_redis_cache.main.primary_access_key sensitive = true }
