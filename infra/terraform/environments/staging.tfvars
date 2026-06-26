# Staging environment — moderate resources, single zone for cost savings.
# postgres_admin_password is NOT set here — injected via CI secret at plan/apply time.

environment        = "staging"
location           = "eastus"
location_secondary = "westus2"
resource_prefix    = "wafagent"

tags = {
  environment = "staging"
  cost-center = "engineering"
  project     = "waf-review-agent"
}

# Networking
vnet_address_space = "10.1.0.0/16"

# AKS
aks_kubernetes_version = "1.30"
aks_system_node_count  = 1   # Cost saving: single system node in staging.
aks_api_node_min       = 1
aks_api_node_max       = 3
aks_agent_node_min     = 0
aks_agent_node_max     = 5
aks_report_node_min    = 0
aks_report_node_max    = 2

# PostgreSQL
postgres_sku                   = "GP_Standard_D2ds_v5"  # 2 vCores in staging.
postgres_storage_mb            = 65536                   # 64 GB
postgres_backup_retention_days = 7

# Azure OpenAI
openai_gpt4o_capacity = 10  # Lower TPM in staging.

# Azure AI Search
search_sku           = "basic"
search_replica_count = 1

# Alerting
alert_action_group_email = "platform-staging@example.com"
