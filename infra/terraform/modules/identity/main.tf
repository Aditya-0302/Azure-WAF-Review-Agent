variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "key_vault_id" { type = string }
variable "acr_id" { type = string }
variable "servicebus_id" { type = string }
variable "storage_account_id" { type = string }
variable "search_id" { type = string }
variable "openai_id" { type = string }
variable "tags" { type = map(string) }

data "azurerm_client_config" "current" {}

# ── One managed identity per workload ─────────────────────────────────────────

locals {
  workloads = toset(["api", "preparation-agent", "extraction-agent", "reasoning-agent", "reporting-agent"])
}

resource "azurerm_user_assigned_identity" "workload" {
  for_each            = local.workloads
  name                = "mi-${var.prefix}-${each.key}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# ── Key Vault RBAC — each workload gets secrets reader ───────────────────────

resource "azurerm_role_assignment" "kv_secrets_user" {
  for_each             = local.workloads
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.workload[each.key].principal_id
}

# ── ACR pull — all workloads (images are pulled by kubelet via node MI,
#    but individual MI pull is also assigned for explicit image pull secrets) ──

resource "azurerm_role_assignment" "acr_pull" {
  for_each             = local.workloads
  scope                = var.acr_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.workload[each.key].principal_id
}

# ── Service Bus — agents are sender+receiver; API is sender only ──────────────

resource "azurerm_role_assignment" "sb_data_owner_api" {
  scope                = var.servicebus_id
  role_definition_name = "Azure Service Bus Data Sender"
  principal_id         = azurerm_user_assigned_identity.workload["api"].principal_id
}

resource "azurerm_role_assignment" "sb_data_owner_agents" {
  for_each             = toset(["preparation-agent", "extraction-agent", "reasoning-agent", "reporting-agent"])
  scope                = var.servicebus_id
  role_definition_name = "Azure Service Bus Data Owner"
  principal_id         = azurerm_user_assigned_identity.workload[each.key].principal_id
}

# ── Blob Storage — reporting agent writes; others read for rule bundles ───────

resource "azurerm_role_assignment" "blob_contributor_reporting" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.workload["reporting-agent"].principal_id
}

resource "azurerm_role_assignment" "blob_reader_reasoning" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.workload["reasoning-agent"].principal_id
}

# ── Azure AI Search — reasoning agent reads the WAF rules index ───────────────

resource "azurerm_role_assignment" "search_reader" {
  scope                = var.search_id
  role_definition_name = "Search Index Data Reader"
  principal_id         = azurerm_user_assigned_identity.workload["reasoning-agent"].principal_id
}

# ── Azure OpenAI — reasoning agent calls GPT-4o ───────────────────────────────

resource "azurerm_role_assignment" "openai_user" {
  scope                = var.openai_id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_user_assigned_identity.workload["reasoning-agent"].principal_id
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "managed_identities" {
  value = { for k, v in azurerm_user_assigned_identity.workload : k => {
    id         = v.id
    client_id  = v.client_id
    principal_id = v.principal_id
  }}
}

output "managed_identity_client_ids" {
  value = { for k, v in azurerm_user_assigned_identity.workload : k => v.client_id }
}
