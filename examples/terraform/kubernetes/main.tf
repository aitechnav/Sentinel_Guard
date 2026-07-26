terraform {
  required_version = ">= 1.5.0"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

resource "kubernetes_namespace" "sentinelguard" {
  metadata {
    name = var.namespace
  }
}

resource "helm_release" "sentinelguard" {
  name       = "sentinelguard"
  namespace  = kubernetes_namespace.sentinelguard.metadata[0].name
  chart      = "${path.module}/../../helm/sentinelguard"

  set {
    name  = "image.repository"
    value = var.image_repository
  }

  set {
    name  = "image.tag"
    value = var.image_tag
  }

  set_sensitive {
    name  = "env.OPENAI_API_KEY"
    value = var.openai_api_key
  }

  set_sensitive {
    name  = "env.SENTINELGUARD_GATEWAY_API_KEY"
    value = var.gateway_api_key
  }

  set_sensitive {
    name  = "env.SENTINELGUARD_AUDIT_SALT"
    value = var.audit_salt
  }
}
