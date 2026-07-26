# Deployment

## Local Gateway

```bash
pip install "sentinelguard[gateway,monitoring]"
sentinelguard init
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080
```

## Docker Compose

```bash
sentinelguard init
cp .env.example .env
docker compose -f docker-compose.sentinelguard.yml up --build
```

## Kubernetes

```bash
kubectl apply -k examples/kubernetes
kubectl -n sentinelguard port-forward svc/sentinelguard-gateway 8080:8080
curl http://localhost:8080/gateway/v1/health
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
