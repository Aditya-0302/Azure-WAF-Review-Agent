variable "prefix" { type = string }
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "action_group_email" { type = string }
variable "tags" { type = map(string) }

# ── Log Analytics Workspace ───────────────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.prefix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  daily_quota_gb      = 10
  tags                = var.tags
}

# ── Application Insights ──────────────────────────────────────────────────────

resource "azurerm_application_insights" "main" {
  name                = "appi-${var.prefix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  tags                = var.tags
}

# ── Azure Monitor Action Group ────────────────────────────────────────────────

resource "azurerm_monitor_action_group" "critical" {
  name                = "ag-${var.prefix}-critical"
  resource_group_name = var.resource_group_name
  short_name          = "waf-crit"
  tags                = var.tags

  email_receiver {
    name                    = "platform-team"
    email_address           = var.action_group_email
    use_common_alert_schema = true
  }
}

# ── Azure Monitor Alert Rules ─────────────────────────────────────────────────

# 1. Assessment pipeline stalled — DLQ message count > 0
resource "azurerm_monitor_metric_alert" "dlq_messages" {
  name                = "alert-${var.prefix}-dlq-messages"
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "Dead-letter queue has messages — assessment pipeline stalled"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.ServiceBus/namespaces"
    metric_name      = "DeadletteredMessages"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

# 2. API p99 latency > 2 seconds
resource "azurerm_monitor_metric_alert" "api_latency_p99" {
  name                = "alert-${var.prefix}-api-latency"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_application_insights.main.id]
  description         = "API p99 response time exceeds 2 seconds"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = var.tags

  criteria {
    metric_namespace = "microsoft.insights/components"
    metric_name      = "requests/duration"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = 2000
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

# 3. API error rate > 1%
resource "azurerm_monitor_metric_alert" "api_error_rate" {
  name                = "alert-${var.prefix}-api-errors"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_application_insights.main.id]
  description         = "API 5xx error rate exceeds 1%"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = var.tags

  dynamic_criteria {
    metric_namespace         = "microsoft.insights/components"
    metric_name              = "requests/failed"
    aggregation              = "Count"
    operator                 = "GreaterThan"
    alert_sensitivity        = "High"
    evaluation_total_count   = 4
    evaluation_failure_count = 2
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

# 4. PostgreSQL CPU > 80%
resource "azurerm_monitor_metric_alert" "postgres_cpu" {
  name                = "alert-${var.prefix}-postgres-cpu"
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "PostgreSQL CPU utilisation is above 80%"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.DBforPostgreSQL/flexibleServers"
    metric_name      = "cpu_percent"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

# 5. PostgreSQL storage > 80%
resource "azurerm_monitor_metric_alert" "postgres_storage" {
  name                = "alert-${var.prefix}-postgres-storage"
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "PostgreSQL storage utilisation is above 80%"
  severity            = 1
  frequency           = "PT15M"
  window_size         = "PT1H"
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.DBforPostgreSQL/flexibleServers"
    metric_name      = "storage_percent"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

# 6. AKS node not ready
resource "azurerm_monitor_metric_alert" "aks_node_not_ready" {
  name                = "alert-${var.prefix}-aks-node"
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "AKS node count in NotReady state > 0"
  severity            = 1
  frequency           = "PT5M"
  window_size         = "PT10M"
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.ContainerService/managedClusters"
    metric_name      = "kube_node_status_condition"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 0

    dimension {
      name     = "status2"
      operator = "Include"
      values   = ["NotReady"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

# 7. Service Bus active message count > 1000 (backpressure signal)
resource "azurerm_monitor_metric_alert" "servicebus_backlog" {
  name                = "alert-${var.prefix}-sb-backlog"
  resource_group_name = var.resource_group_name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]
  description         = "Service Bus active message count exceeds 1000 — KEDA scale-up may be insufficient"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.ServiceBus/namespaces"
    metric_name      = "ActiveMessages"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 1000
  }

  action {
    action_group_id = azurerm_monitor_action_group.critical.id
  }
}

data "azurerm_client_config" "current" {}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "log_analytics_workspace_id"   { value = azurerm_log_analytics_workspace.main.id }
output "log_analytics_workspace_name" { value = azurerm_log_analytics_workspace.main.name }
output "app_insights_connection_string" {
  value     = azurerm_application_insights.main.connection_string
  sensitive = true
}
output "app_insights_instrumentation_key" {
  value     = azurerm_application_insights.main.instrumentation_key
  sensitive = true
}
