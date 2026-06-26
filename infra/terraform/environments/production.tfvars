# Production environment — full HA configuration.
# postgres_admin_password is NOT set here — injected via CI secret at plan/apply time.

environment        = "production"
location           = "eastus"
location_secondary = "westus2"
resource_prefix    = "wafagent"

tags = {
  environment = "production"
  cost-center = "product"
  project     = "waf-review-agent"
  criticality = "high"
}

# Networking
vnet_address_space = "10.0.0.0/16"

# AKS — zone-redundant system pool + 4 node pools.
aks_kubernetes_version = "1.30"
aks_system_node_count  = 3   # One per AZ.
aks_api_node_min       = 2
aks_api_node_max       = 10
aks_agent_node_min     = 1
aks_agent_node_max     = 10
aks_report_node_min    = 1
aks_report_node_max    = 3

# PostgreSQL — D4ds_v5 with ZRS GRS backup.
postgres_sku                   = "GP_Standard_D4ds_v5"  # 4 vCores, 32GB RAM.
postgres_storage_mb            = 131072                   # 128 GB
postgres_backup_retention_days = 35

# Azure OpenAI — GPT-4o Standard at 40K TPM.
openai_gpt4o_capacity = 40

# Azure AI Search — Standard S1 with 2 replicas (HA).
search_sku           = "standard"
search_replica_count = 2

# Alerting
alert_action_group_email = "platform-oncall@example.com"
