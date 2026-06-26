output "resource_group_name" {
  description = "Primary resource group name"
  value       = azurerm_resource_group.main.name
}

output "aks_cluster_name" {
  description = "AKS cluster name"
  value       = module.aks.cluster_name
}

output "aks_oidc_issuer_url" {
  description = "AKS OIDC issuer URL for federated credentials"
  value       = module.aks.oidc_issuer_url
}

output "acr_login_server" {
  description = "ACR login server URL"
  value       = module.storage.acr_login_server
}

output "key_vault_uri" {
  description = "Key Vault URI"
  value       = module.security.key_vault_uri
}

output "servicebus_namespace" {
  description = "Service Bus namespace hostname"
  value       = module.messaging.servicebus_namespace_hostname
}

output "postgres_fqdn" {
  description = "PostgreSQL Flexible Server FQDN"
  value       = module.data.postgres_fqdn
  sensitive   = true
}

output "openai_endpoint" {
  description = "Azure OpenAI endpoint"
  value       = module.ai.openai_endpoint
}

output "search_endpoint" {
  description = "Azure AI Search endpoint"
  value       = module.ai.search_endpoint
}

output "storage_account_url" {
  description = "Blob Storage primary endpoint"
  value       = module.storage.storage_account_blob_endpoint
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = module.observability.log_analytics_workspace_id
}

output "managed_identity_client_ids" {
  description = "Client IDs for each workload managed identity"
  value       = module.identity.managed_identity_client_ids
}
