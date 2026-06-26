variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "kubernetes_version" { type = string }
variable "subnet_system_id" { type = string }
variable "subnet_api_id" { type = string }
variable "subnet_agent_id" { type = string }
variable "subnet_report_id" { type = string }
variable "acr_id" { type = string }
variable "log_analytics_workspace_id" { type = string }
variable "system_node_count" { type = number }
variable "api_node_min" { type = number }
variable "api_node_max" { type = number }
variable "agent_node_min" { type = number }
variable "agent_node_max" { type = number }
variable "report_node_min" { type = number }
variable "report_node_max" { type = number }
variable "tags" { type = map(string) }

resource "azurerm_kubernetes_cluster" "main" {
  name                      = "aks-${var.prefix}"
  location                  = var.location
  resource_group_name       = var.resource_group_name
  dns_prefix                = var.prefix
  kubernetes_version        = var.kubernetes_version
  private_cluster_enabled   = true
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  # System node pool — Standard_DS2_v2 — runs control-plane add-ons.
  default_node_pool {
    name                         = "system"
    node_count                   = var.system_node_count
    vm_size                      = "Standard_DS2_v2"
    vnet_subnet_id               = var.subnet_system_id
    os_disk_size_gb              = 100
    os_disk_type                 = "Managed"
    type                         = "VirtualMachineScaleSets"
    only_critical_addons_enabled = true
    zones                        = ["1", "2", "3"]
    node_labels = {
      "agentpool" = "system"
    }
  }

  # Azure CNI — required for private cluster with custom subnets.
  network_profile {
    network_plugin    = "azure"
    network_policy    = "cilium"
    network_data_plane = "cilium"
    load_balancer_sku = "standard"
    outbound_type     = "userAssignedNATGateway"
  }

  # Managed identity for cluster itself.
  identity {
    type = "SystemAssigned"
  }

  # Azure Monitor — Container Insights.
  oms_agent {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  azure_active_directory_role_based_access_control {
    managed   = true
    azure_rbac_enabled = true
  }

  # Key Vault Secrets Store CSI driver.
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  auto_scaler_profile {
    balance_similar_node_groups      = true
    expander                         = "least-waste"
    max_graceful_termination_sec     = 600
    scale_down_delay_after_add       = "10m"
    scale_down_unneeded              = "10m"
    skip_nodes_with_local_storage    = false
    skip_nodes_with_system_pods      = true
  }

  maintenance_window {
    allowed {
      day   = "Sunday"
      hours = [2, 3]
    }
  }

  tags = var.tags
}

# ── ACR pull permission for cluster identity ──────────────────────────────────

resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                = var.acr_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}

# ── Additional node pools ─────────────────────────────────────────────────────

resource "azurerm_kubernetes_cluster_node_pool" "api" {
  name                  = "apipool"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D4s_v5"
  vnet_subnet_id        = var.subnet_api_id
  enable_auto_scaling   = true
  min_count             = var.api_node_min
  max_count             = var.api_node_max
  os_disk_size_gb       = 128
  zones                 = ["1", "2", "3"]
  node_labels           = { "agentpool" = "apipool" }
  node_taints           = ["workload=api:NoSchedule"]
  tags                  = var.tags
}

resource "azurerm_kubernetes_cluster_node_pool" "agent" {
  name                  = "agentpool"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D4s_v5"
  vnet_subnet_id        = var.subnet_agent_id
  enable_auto_scaling   = true
  min_count             = var.agent_node_min
  max_count             = var.agent_node_max
  os_disk_size_gb       = 128
  zones                 = ["1", "2", "3"]
  node_labels           = { "agentpool" = "agentpool" }
  tags                  = var.tags
}

resource "azurerm_kubernetes_cluster_node_pool" "report" {
  name                  = "reportpool"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D4s_v5"
  vnet_subnet_id        = var.subnet_report_id
  enable_auto_scaling   = true
  min_count             = var.report_node_min
  max_count             = var.report_node_max
  os_disk_size_gb       = 128
  zones                 = ["1", "2", "3"]
  node_labels           = { "agentpool" = "reportpool" }
  node_taints           = ["workload=reporting:NoSchedule"]
  tags                  = var.tags
}

# ── Diagnostics → Log Analytics ───────────────────────────────────────────────

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "diag-aks"
  target_resource_id         = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "kube-apiserver" }
  enabled_log { category = "kube-controller-manager" }
  enabled_log { category = "kube-scheduler" }
  enabled_log { category = "kube-audit" }
  enabled_log { category = "kube-audit-admin" }
  metric { category = "AllMetrics" enabled = true }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "cluster_name"     { value = azurerm_kubernetes_cluster.main.name }
output "cluster_id"       { value = azurerm_kubernetes_cluster.main.id }
output "oidc_issuer_url"  { value = azurerm_kubernetes_cluster.main.oidc_issuer_url }
output "kube_config"      { value = azurerm_kubernetes_cluster.main.kube_config[0] sensitive = true }
output "kubelet_identity" { value = azurerm_kubernetes_cluster.main.kubelet_identity[0] }
