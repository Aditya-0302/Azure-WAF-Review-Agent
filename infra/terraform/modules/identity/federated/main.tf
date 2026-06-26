variable "aks_oidc_issuer_url" { type = string }
variable "managed_identities" {
  type = map(object({
    id           = string
    client_id    = string
    principal_id = string
  }))
}
variable "kubernetes_namespace" { type = string }

locals {
  # Map workload name → Kubernetes ServiceAccount name used in Helm charts.
  sa_names = {
    "api"               = "waf-api"
    "preparation-agent" = "waf-preparation-agent"
    "extraction-agent"  = "waf-extraction-agent"
    "reasoning-agent"   = "waf-reasoning-agent"
    "reporting-agent"   = "waf-reporting-agent"
  }
}

resource "azurerm_federated_identity_credential" "workloads" {
  for_each = var.managed_identities

  # Extract MI resource group and name from the MI id.
  name                = "fic-${each.key}"
  resource_group_name = regex("resourceGroups/([^/]+)/", each.value.id)[0]
  parent_id           = each.value.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.kubernetes_namespace}:${local.sa_names[each.key]}"
}
