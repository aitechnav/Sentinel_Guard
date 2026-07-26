output "namespace" {
  description = "Namespace where SentinelGuard is deployed."
  value       = kubernetes_namespace.sentinelguard.metadata[0].name
}

output "service_name" {
  description = "SentinelGuard gateway Kubernetes service name."
  value       = "sentinelguard-sentinelguard"
}
