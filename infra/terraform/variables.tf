variable "environment" {
  description = "Deployment environment: staging | production"
  type        = string
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be 'staging' or 'production'."
  }
}

variable "location" {
  description = "Primary Azure region"
  type        = string
  default     = "eastus"
}

variable "location_secondary" {
  description = "Secondary Azure region for geo-redundancy"
  type        = string
  default     = "westus2"
}

variable "resource_prefix" {
  description = "Short prefix applied to all resource names (max 8 chars)"
  type        = string
  default     = "wafagent"
  validation {
    condition     = length(var.resource_prefix) <= 8
    error_message = "resource_prefix must be 8 characters or fewer."
  }
}

variable "tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default     = {}
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "vnet_address_space" {
  description = "VNet address space"
  type        = string
  default     = "10.0.0.0/16"
}

# ── AKS ──────────────────────────────────────────────────────────────────────

variable "aks_kubernetes_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.30"
}

variable "aks_system_node_count" {
  description = "Number of nodes in the system node pool"
  type        = number
  default     = 3
}

variable "aks_api_node_min" {
  description = "Min nodes in the API node pool"
  type        = number
  default     = 2
}

variable "aks_api_node_max" {
  description = "Max nodes in the API node pool"
  type        = number
  default     = 10
}

variable "aks_agent_node_min" {
  description = "Min nodes in the general agent pool"
  type        = number
  default     = 1
}

variable "aks_agent_node_max" {
  description = "Max nodes in the general agent pool"
  type        = number
  default     = 10
}

variable "aks_report_node_min" {
  description = "Min nodes in the report (D4s_v5) pool"
  type        = number
  default     = 1
}

variable "aks_report_node_max" {
  description = "Max nodes in the report (D4s_v5) pool"
  type        = number
  default     = 3
}

# ── PostgreSQL ────────────────────────────────────────────────────────────────

variable "postgres_sku" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "GP_Standard_D4ds_v5"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage in MB"
  type        = number
  default     = 131072  # 128 GB
}

variable "postgres_backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 35
}

variable "postgres_admin_password" {
  description = "PostgreSQL admin password — sourced from CI secret, never in tfvars"
  type        = string
  sensitive   = true
}

# ── Azure OpenAI ──────────────────────────────────────────────────────────────

variable "openai_gpt4o_capacity" {
  description = "GPT-4o PTU or TPM capacity units"
  type        = number
  default     = 40
}

# ── Azure AI Search ───────────────────────────────────────────────────────────

variable "search_sku" {
  description = "Azure AI Search pricing tier"
  type        = string
  default     = "standard"
}

variable "search_replica_count" {
  description = "Number of AI Search replicas"
  type        = number
  default     = 2
}

# ── Notifications ─────────────────────────────────────────────────────────────

variable "alert_action_group_email" {
  description = "Email address for Azure Monitor alert notifications"
  type        = string
}
