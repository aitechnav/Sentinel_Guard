# Deployment

## Local Gateway

```bash
pip install "sentinelguard[gateway,monitoring]"
sentinelguard init
export OPENAI_API_KEY="sk-..."
export SENTINELGUARD_GATEWAY_API_KEY="$(sentinelguard token)"
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080
```

Local apps and IDEs use:

```text
Base URL: http://localhost:8080/v1
API key:  the same sgw_... value from SENTINELGUARD_GATEWAY_API_KEY
```

## Docker Compose

```bash
sentinelguard init --with-env
# Edit .env and set at least one upstream provider key, such as OPENAI_API_KEY.
docker compose -f docker-compose.sentinelguard.yml up --build
```

Apps in the same Compose network use:

```text
Base URL: http://sentinelguard-gateway:8080/v1
API key:  the same sgw_... value from SENTINELGUARD_GATEWAY_API_KEY
```

## Kubernetes

```bash
kubectl apply -k examples/kubernetes
kubectl -n sentinelguard port-forward svc/sentinelguard-gateway 8080:8080
curl http://localhost:8080/gateway/v1/health
```

In-cluster apps use:

```text
Base URL: http://sentinelguard-gateway.sentinelguard.svc.cluster.local:8080/v1
API key:  the same sgw_... value from SENTINELGUARD_GATEWAY_API_KEY
```

For EC2, ECS, another EKS cluster, or another VPC, expose the gateway through a
private DNS name, internal load balancer, PrivateLink, VPN, or peering route:

```text
Base URL: https://sentinelguard.internal.example.com/v1
API key:  app-specific SentinelGuard virtual key
```

## Helm And Terraform

Examples are available in:

- `examples/helm/sentinelguard`
- `examples/terraform/kubernetes`

Use the stable management API for probes, dashboards, and automation:

```text
/gateway/v1/health
/gateway/v1/routes
/gateway/v1/provider-health
```

For detailed client wiring patterns, see
[Client Integration Patterns](client-integrations.md).
