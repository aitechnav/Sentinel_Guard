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

For Docker Compose, put upstream provider keys such as `OPENAI_API_KEY` in the
Compose `.env` file or Docker secrets so only the SentinelGuard container
receives them. To update provider keys from the dashboard instead, also set a
stable `SENTINELGUARD_ENCRYPTION_KEY`. `sentinelguard init --with-env` generates
one for local Compose. Dashboard-entered provider keys are then stored encrypted
in the gateway SQLite volume and shown only as masked hints.

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

For Kubernetes, keep upstream provider keys in Kubernetes Secrets, external
secret operators, or your cloud secret manager and expose them to SentinelGuard
as environment variables referenced by `api_key_env`. Dashboard-entered provider
keys are supported for self-managed deployments, but they are stored in the
gateway SQLite state volume, not written back to a Kubernetes Secret.

For EC2, ECS, another EKS cluster, or another VPC, expose the gateway through a
private DNS name, internal load balancer, PrivateLink, VPN, or peering route:

```text
Base URL: https://sentinelguard.internal.example.com/v1
API key:  app-specific SentinelGuard virtual key
```

## Capacity And Scaling

SentinelGuard does not have a fixed built-in user limit. Capacity depends on
in-flight LLM requests, scanner cost, upstream provider latency, provider rate
limits, and how many gateway replicas are running.
In Kubernetes or ECS, treat SentinelGuard as a horizontally scalable gateway:
capacity grows with replicas, CPU/memory allocation, and upstream provider
quota.

Think in requests, not just users:

```text
required in-flight capacity ~= requests per second * p95 end-to-end latency seconds
```

For example, if clients send 10 requests per second and the p95 upstream model
latency is 6 seconds, the gateway needs capacity for roughly 60 concurrent
in-flight requests, plus headroom.

Practical starting points:

| Deployment shape | Typical use | Starting expectation |
| --- | --- | --- |
| Laptop or single small VM | Development, demos, one team | Small non-production traffic |
| One production-sized gateway replica with cloud LLMs | Internal service or one app team | Hundreds of concurrent in-flight HTTP requests can be realistic when scanners are lightweight and upstream latency dominates |
| Multiple Kubernetes, ECS, or EC2 replicas behind a Service or internal load balancer | Shared production gateway | Scale horizontally to hundreds or thousands of concurrent in-flight requests, bounded by CPU, memory, scanner cost, upstream provider quotas, and network limits |
| Local model-backed detection on CPU | Higher-security detection, slower path | Lower concurrency; benchmark before production |
| Local model-backed detection on GPU | Higher-security detection at scale | Depends on model, GPU memory, batching, and replica count |

Provider-level concurrency limits are optional safety valves, not product
ceilings. Use them to avoid overwhelming one upstream model provider or local
model server. Tune them per replica from your provider quota and observed
latency:

```yaml
gateway:
  routing_strategy: least-busy
  providers:
    - name: openai-fast
      max_parallel_requests: 250   # per gateway replica; tune for your quota
    - name: anthropic-smart
      max_parallel_requests: 150   # per gateway replica; tune for your quota
    - name: ollama-private
      max_parallel_requests: 25    # local model servers are usually lower
```

Those limits are per gateway process or pod. If you run three replicas, each
replica has its own provider runtime state, so the effective configured
provider concurrency is roughly:

```text
effective provider concurrency ~= replicas * max_parallel_requests
```

You can also omit `max_parallel_requests` for a provider route if you want no
SentinelGuard-side provider throttle and prefer to rely on upstream provider
rate limits, autoscaling, and platform controls.

For production:

- Run multiple gateway replicas behind a Kubernetes Service or internal load
  balancer, ECS service, or EC2 target group.
- Keep the gateway close to the calling services to reduce network latency.
- Use provider pools and `routing_strategy: least-busy` or
  `routing_strategy: latency-based-routing` when multiple upstream providers
  serve the same model route.
- Set `max_parallel_requests` per provider route to avoid exhausting upstream
  APIs or local model servers.
- Use Prometheus metrics to watch request rate, detection counts, latency,
  provider failures, and saturation.
- Keep SQLite for single-node/simple deployments. For multi-replica production,
  treat usage and budget accounting carefully because pod-local memory or
  pod-local SQLite does not provide a global counter across replicas.
- Benchmark with your enabled scanners, your prompt sizes, your streaming mode,
  and your provider latency before publishing a capacity number.

Buffered streaming is safe but holds the client request open while the gateway
collects and scans the complete upstream response. Streaming-heavy workloads
need more in-flight capacity than short non-streaming calls.

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
