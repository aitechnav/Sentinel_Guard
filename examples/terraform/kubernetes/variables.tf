variable "kubeconfig_path" {
  description = "Path to kubeconfig used by Terraform providers."
  type        = string
  default     = "~/.kube/config"
}

variable "namespace" {
  description = "Kubernetes namespace for SentinelGuard."
  type        = string
  default     = "sentinelguard"
}

variable "image_repository" {
  description = "SentinelGuard gateway image repository."
  type        = string
  default     = "sentinelguard-gateway"
}

variable "image_tag" {
  description = "SentinelGuard gateway image tag."
  type        = string
  default     = "latest"
}

variable "openai_api_key" {
  description = "Upstream OpenAI API key."
  type        = string
  sensitive   = true
}

variable "gateway_api_key" {
  description = "Client-facing SentinelGuard gateway key."
  type        = string
  sensitive   = true
}

variable "audit_salt" {
  description = "Salt used for privacy-safe audit hashing."
  type        = string
  sensitive   = true
  default     = "change-me"
}
