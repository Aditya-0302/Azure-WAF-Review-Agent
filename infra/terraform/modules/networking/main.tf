variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "address_space" { type = string }
variable "tags" { type = map(string) }

locals {
  # Carve address space deterministically from the supplied /16.
  # Default 10.0.0.0/16 → subnets below.
  base = cidrsubnet(var.address_space, 0, 0)
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.prefix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = [var.address_space]
  tags                = var.tags
}

# ── Subnets ───────────────────────────────────────────────────────────────────

resource "azurerm_subnet" "aks_system" {
  name                 = "snet-aks-system"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.address_space, 6, 0)]   # /22 — x.x.0.0/22
}

resource "azurerm_subnet" "aks_api" {
  name                 = "snet-aks-api"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.address_space, 6, 1)]   # /22 — x.x.4.0/22
}

resource "azurerm_subnet" "aks_agent" {
  name                 = "snet-aks-agent"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.address_space, 6, 2)]   # /22 — x.x.8.0/22
}

resource "azurerm_subnet" "aks_report" {
  name                 = "snet-aks-report"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.address_space, 8, 48)]  # /24 — x.x.12.0/24
}

resource "azurerm_subnet" "private_endpoints" {
  name                                      = "snet-private-endpoints"
  resource_group_name                       = var.resource_group_name
  virtual_network_name                      = azurerm_virtual_network.main.name
  address_prefixes                          = [cidrsubnet(var.address_space, 8, 64)]  # /24
  private_endpoint_network_policies_enabled = false
}

resource "azurerm_subnet" "postgres" {
  name                 = "snet-postgres"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.address_space, 12, 272)]  # /28

  delegation {
    name = "postgres-delegation"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ── NSGs ──────────────────────────────────────────────────────────────────────

resource "azurerm_network_security_group" "aks" {
  name                = "nsg-${var.prefix}-aks"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "allow-https-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "private_endpoints" {
  name                = "nsg-${var.prefix}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "aks_system" {
  subnet_id                 = azurerm_subnet.aks_system.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

resource "azurerm_subnet_network_security_group_association" "aks_api" {
  subnet_id                 = azurerm_subnet.aks_api.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

resource "azurerm_subnet_network_security_group_association" "aks_agent" {
  subnet_id                 = azurerm_subnet.aks_agent.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

resource "azurerm_subnet_network_security_group_association" "aks_report" {
  subnet_id                 = azurerm_subnet.aks_report.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  subnet_id                 = azurerm_subnet.private_endpoints.id
  network_security_group_id = azurerm_network_security_group.private_endpoints.id
}

# ── Private DNS zones ─────────────────────────────────────────────────────────

locals {
  private_dns_zones = [
    "privatelink.postgres.database.azure.com",
    "privatelink.servicebus.windows.net",
    "privatelink.vaultcore.azure.net",
    "privatelink.blob.core.windows.net",
    "privatelink.azurecr.io",
    "privatelink.openai.azure.com",
    "privatelink.search.windows.net",
    "privatelink.redis.cache.windows.net",
  ]
}

resource "azurerm_private_dns_zone" "zones" {
  for_each            = toset(local.private_dns_zones)
  name                = each.key
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "links" {
  for_each              = azurerm_private_dns_zone.zones
  name                  = "link-${replace(each.key, ".", "-")}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = each.value.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
  tags                  = var.tags
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "vnet_id"                       { value = azurerm_virtual_network.main.id }
output "vnet_name"                     { value = azurerm_virtual_network.main.name }
output "subnet_aks_system_id"          { value = azurerm_subnet.aks_system.id }
output "subnet_aks_api_id"             { value = azurerm_subnet.aks_api.id }
output "subnet_aks_agent_id"           { value = azurerm_subnet.aks_agent.id }
output "subnet_aks_report_id"          { value = azurerm_subnet.aks_report.id }
output "subnet_postgres_id"            { value = azurerm_subnet.postgres.id }
output "subnet_private_endpoints_id"   { value = azurerm_subnet.private_endpoints.id }
output "private_dns_zone_ids"          { value = { for k, v in azurerm_private_dns_zone.zones : k => v.id } }
