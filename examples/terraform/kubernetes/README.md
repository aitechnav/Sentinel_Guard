# SentinelGuard Terraform Kubernetes Example

This example deploys the SentinelGuard Helm chart with Terraform.

```bash
terraform init
terraform apply \
  -var='openai_api_key=sk-...' \
  -var="gateway_api_key=$(sentinelguard token)" \
  -var="audit_salt=$(sentinelguard token --prefix sgaudit)"
```

The example assumes your local Kubernetes context already points at the target
cluster. For production, store secrets in your cloud secret manager or external
secret operator instead of passing them on the command line.
