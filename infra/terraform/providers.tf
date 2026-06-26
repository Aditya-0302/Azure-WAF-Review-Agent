terraform {
  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.52"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
  }

  # Remote state in Azure Blob Storage — bootstrap separately before first apply.
  backend "azurerm" {
    resource_group_name  = "rg-wafagent-tfstate"
    storage_account_name = "wafagenttfstate"
    container_name       = "tfstate"
    key                  = "wafagent.tfstate"
    use_oidc             = true
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }
  use_oidc = true
}

provider "azuread" {
  use_oidc = true
}

provider "helm" {
  kubernetes {
    host                   = module.aks.kube_config.host
    cluster_ca_certificate = base64decode(module.aks.kube_config.cluster_ca_certificate)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "kubelogin"
      args = [
        "convert-kubeconfig",
        "-l", "workloadidentity",
        "--server-id", module.aks.kube_config.host,
      ]
    }
  }
}

provider "kubernetes" {
  host                   = module.aks.kube_config.host
  cluster_ca_certificate = base64decode(module.aks.kube_config.cluster_ca_certificate)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "kubelogin"
    args        = ["convert-kubeconfig", "-l", "workloadidentity"]
  }
}
