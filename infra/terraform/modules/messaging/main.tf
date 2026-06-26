variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_pe_id" { type = string }
variable "vnet_id" { type = string }
variable "tags" { type = map(string) }

# ── Service Bus Namespace (Premium — required for private endpoints + zones) ──

resource "azurerm_servicebus_namespace" "main" {
  name                          = "sb-${var.prefix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  sku                           = "Premium"
  capacity                      = 1
  zone_redundant                = true
  local_auth_enabled            = false   # Workload Identity only — no connection strings.
  public_network_access_enabled = false
  minimum_tls_version           = "1.2"
  tags                          = var.tags
}

resource "azurerm_private_endpoint" "servicebus" {
  name                = "pe-${var.prefix}-sb"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.subnet_pe_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-sb"
    private_connection_resource_id = azurerm_servicebus_namespace.main.id
    subresource_names              = ["namespace"]
    is_manual_connection           = false
  }
}

# ── Queues ────────────────────────────────────────────────────────────────────

locals {
  queues = {
    "assessment-created" = {
      max_delivery_count         = 5
      lock_duration              = "PT5M"
      message_ttl                = "P7D"
      dead_lettering_on_expiry   = true
    }
    "extraction-requested" = {
      max_delivery_count         = 5
      lock_duration              = "PT10M"
      message_ttl                = "P7D"
      dead_lettering_on_expiry   = true
    }
    "reasoning-requested" = {
      max_delivery_count         = 3
      lock_duration              = "PT15M"
      message_ttl                = "P7D"
      dead_lettering_on_expiry   = true
    }
    "reporting-requested" = {
      max_delivery_count         = 5
      lock_duration              = "PT5M"
      message_ttl                = "P7D"
      dead_lettering_on_expiry   = true
    }
    "assessment-cancelled" = {
      max_delivery_count         = 3
      lock_duration              = "PT1M"
      message_ttl                = "P1D"
      dead_lettering_on_expiry   = false
    }
    "webhook-delivery" = {
      max_delivery_count         = 10
      lock_duration              = "PT2M"
      message_ttl                = "P3D"
      dead_lettering_on_expiry   = true
    }
  }
}

resource "azurerm_servicebus_queue" "queues" {
  for_each     = local.queues
  name         = each.key
  namespace_id = azurerm_servicebus_namespace.main.id

  max_delivery_count                    = each.value.max_delivery_count
  lock_duration                         = each.value.lock_duration
  default_message_ttl                   = each.value.message_ttl
  dead_lettering_on_message_expiration  = each.value.dead_lettering_on_expiry
  enable_partitioning                   = false  # Premium supports partitioning but not needed here.
  requires_duplicate_detection          = false
  max_size_in_megabytes                 = 1024
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "servicebus_id"                  { value = azurerm_servicebus_namespace.main.id }
output "servicebus_namespace_hostname"  { value = "${azurerm_servicebus_namespace.main.name}.servicebus.windows.net" }
output "queue_ids"                      { value = { for k, v in azurerm_servicebus_queue.queues : k => v.id } }
