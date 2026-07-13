# SentinelGuard Gateway on Kubernetes

Run SentinelGuard as an OpenAI-compatible LLM gateway service in Kubernetes.
Apps, users, and AI IDEs can point their OpenAI-compatible base URL to this
gateway so prompts and model responses are scanned centrally.

## Build and publish the image

Build the default gateway image:

```bash
docker build -t registry.example.com/sentinelguard-gateway:0.0.8 .
docker push registry.example.com/sentinelguard-gateway:0.0.8
```

For local Hugging Face model-backed detection inside the gateway image:

```bash
docker build \
  --build-arg SENTINELGUARD_EXTRAS=gateway,monitoring,models \
  -t registry.example.com/sentinelguard-gateway:0.0.8-models .
docker push registry.example.com/sentinelguard-gateway:0.0.8-models
```

Update `deployment.yaml` to use your pushed image.

## Create secrets

Create the namespace first:

```bash
kubectl apply -f examples/kubernetes/namespace.yaml
```

Create the gateway Secret:

```bash
kubectl create secret generic sentinelguard-gateway-secrets \
  -n sentinelguard \
  --from-literal=OPENAI_API_KEY="$OPENAI_API_KEY" \
  --from-literal=SENTINELGUARD_GATEWAY_API_KEY="shared-gateway-token" \
  --from-literal=SENTINELGUARD_AUDIT_SALT="$(openssl rand -hex 32)"
```

For Anthropic or Gemini, add the matching key:

```bash
--from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"
--from-literal=GEMINI_API_KEY="$GEMINI_API_KEY"
```

You can also copy `secret.example.yaml`, replace the placeholder values, and
apply it. Do not commit real secret values.

## Deploy

```bash
kubectl apply -k examples/kubernetes
kubectl -n sentinelguard rollout status deployment/sentinelguard-gateway
```

Check health:

```bash
kubectl -n sentinelguard port-forward svc/sentinelguard-gateway 8080:8080
curl http://localhost:8080/gateway/health
```

## Configure apps and IDEs

For in-cluster apps:

```text
http://sentinelguard-gateway.sentinelguard.svc.cluster.local:8080/v1
```

For local IDEs such as Cursor, VS Code extensions, Kiro, or Codex-compatible
OpenAI clients, use port-forwarding or an internal Ingress/LoadBalancer and set
the OpenAI-compatible base URL to:

```text
http://localhost:8080/v1
```

Use `shared-gateway-token` as the client API key when gateway client auth is
enabled.

## Optional Ingress

Edit `ingress.example.yaml` for your ingress class, hostname, and TLS setup,
then apply it:

```bash
kubectl apply -f examples/kubernetes/ingress.example.yaml
```

Keep this endpoint private to your network, VPN, or internal platform controls.
The gateway may hold upstream LLM API keys.

## Model cache note

The default deployment uses an ephemeral Hugging Face cache. If you run the
`models` image in production, replace the `emptyDir` cache volume with a
PersistentVolumeClaim so model downloads survive pod restarts.
