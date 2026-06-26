locals {
  prefix = "${var.resource_prefix}-${var.environment}"

  common_tags = merge(var.tags, {
    environment = var.environment
    managed-by  = "terraform"
    project     = "waf-review-agent"
  })
}

# ── Resource Groups ───────────────────────────────────────────────────────────

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.prefix}"
  location = var.location
  tags     = local.common_tags
}

resource "azurerm_resource_group" "secondary" {
  name     = "rg-${local.prefix}-secondary"
  location = var.location_secondary
  tags     = local.common_tags
}

# ── Networking ────────────────────────────────────────────────────────────────

module "networking" {
  source = "./modules/networking"

  prefix              = local.prefix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  address_space       = var.vnet_address_space
  tags                = local.common_tags
}

# ── Key Vault + Secret Store ──────────────────────────────────────────────────

module "security" {
  source = "./modules/security"

  prefix              = local.prefix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  subnet_pe_id        = module.networking.subnet_private_endpoints_id
  vnet_id             = module.networking.vnet_id
  tags                = local.common_tags

  depends_on = [module.networking]
}

# ── Managed Identities + RBAC ─────────────────────────────────────────────────

module "identity" {
  source = "./modules/identity"

  prefix              = local.prefix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  key_vault_id        = module.security.key_vault_id
  acr_id              = module.storage.acr_id
  servicebus_id       = module.messaging.servicebus_id
  storage_account_id  = module.storage.storage_account_id
  search_id           = module.ai.search_id
  openai_id           = module.ai.openai_id
  tags                = local.common_tags

  depends_on = [module.security, module.storage, module.messaging, module.ai]
}

# ── PostgreSQL + Redis ────────────────────────────────────────────────────────

module "data" {
  source = "./modules/data"

  prefix                     = local.prefix
  resource_group_name        = azurerm_resource_group.main.name
  location                   = var.location
  subnet_postgres_id         = module.networking.subnet_postgres_id
  subnet_pe_id               = module.networking.subnet_private_endpoints_id
  vnet_id                    = module.networking.vnet_id
  postgres_sku               = var.postgres_sku
  postgres_storage_mb        = var.postgres_storage_mb
  backup_retention_days      = var.postgres_backup_retention_days
  admin_password             = var.postgres_admin_password
  log_analytics_workspace_id = module.observability.log_analytics_workspace_id
  tags                       = local.common_tags

  depends_on = [module.networking, module.observability]
}

# ── Service Bus ───────────────────────────────────────────────────────────────

module "messaging" {
  source = "./modules/messaging"

  prefix              = local.prefix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  subnet_pe_id        = module.networking.subnet_private_endpoints_id
  vnet_id             = module.networking.vnet_id
  tags                = local.common_tags

  depends_on = [module.networking]
}

# ── Azure OpenAI + AI Search ──────────────────────────────────────────────────

module "ai" {
  source = "./modules/ai"

  prefix                 = local.prefix
  resource_group_name    = azurerm_resource_group.main.name
  location               = var.location
  subnet_pe_id           = module.networking.subnet_private_endpoints_id
  vnet_id                = module.networking.vnet_id
  openai_gpt4o_capacity  = var.openai_gpt4o_capacity
  search_sku             = var.search_sku
  search_replica_count   = var.search_replica_count
  key_vault_id           = module.security.key_vault_id
  tags                   = local.common_tags

  depends_on = [module.networking, module.security]
}

# ── Container Registry + Blob Storage ────────────────────────────────────────

module "storage" {
  source = "./modules/storage"

  prefix               = local.prefix
  resource_group_name  = azurerm_resource_group.main.name
  location             = var.location
  location_secondary   = var.location_secondary
  subnet_pe_id         = module.networking.subnet_private_endpoints_id
  vnet_id              = module.networking.vnet_id
  tags                 = local.common_tags

  depends_on = [module.networking]
}

# ── AKS Cluster ───────────────────────────────────────────────────────────────

module "aks" {
  source = "./modules/aks"

  prefix                     = local.prefix
  resource_group_name        = azurerm_resource_group.main.name
  location                   = var.location
  kubernetes_version         = var.aks_kubernetes_version
  subnet_system_id           = module.networking.subnet_aks_system_id
  subnet_api_id              = module.networking.subnet_aks_api_id
  subnet_agent_id            = module.networking.subnet_aks_agent_id
  subnet_report_id           = module.networking.subnet_aks_report_id
  acr_id                     = module.storage.acr_id
  log_analytics_workspace_id = module.observability.log_analytics_workspace_id
  system_node_count          = var.aks_system_node_count
  api_node_min               = var.aks_api_node_min
  api_node_max               = var.aks_api_node_max
  agent_node_min             = var.aks_agent_node_min
  agent_node_max             = var.aks_agent_node_max
  report_node_min            = var.aks_report_node_min
  report_node_max            = var.aks_report_node_max
  tags                       = local.common_tags

  depends_on = [module.networking, module.observability, module.storage]
}

# ── Observability ─────────────────────────────────────────────────────────────

module "observability" {
  source = "./modules/observability"

  prefix              = local.prefix
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  action_group_email  = var.alert_action_group_email
  tags                = local.common_tags
}

# ── Federated Credentials (post-AKS OIDC) ───────────────────────────────────

module "federated_credentials" {
  source = "./modules/identity/federated"

  aks_oidc_issuer_url   = module.aks.oidc_issuer_url
  managed_identities    = module.identity.managed_identities
  kubernetes_namespace  = "wafagent-${var.environment}"

  depends_on = [module.aks, module.identity]
}
