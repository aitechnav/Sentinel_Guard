# LLM Gateway

Gateway mode lets SentinelGuard run as a separate proxy in front of model
providers. Applications, SDKs, and IDEs send OpenAI-compatible traffic to
SentinelGuard first.

```text
Application or IDE
  -> SentinelGuard /v1/chat/completions
  -> OpenAI, Anthropic, Gemini, Ollama, Mistral, DeepSeek, or another provider
```

## Start Locally

```bash
pip install "sentinelguard[gateway,monitoring]"
export OPENAI_API_KEY="sk-..."
export SENTINELGUARD_GATEWAY_API_KEY="local-gateway-token"

sentinelguard init
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080
```

## Configure Apps And IDEs

Use this OpenAI-compatible base URL:

```text
http://localhost:8080/v1
```

If gateway client authentication is enabled, use the configured gateway token as
the client API key.

## Change Gateway Settings

Generated gateway YAML can be changed from the CLI:

```bash
sentinelguard gateway-config set gateway.routing_strategy weighted --file sentinelguard-gateway.yaml
sentinelguard gateway-config set gateway.fallback_enabled true --file sentinelguard-gateway.yaml
sentinelguard gateway-config set gateway.providers.0.priority 5 --file sentinelguard-gateway.yaml
sentinelguard gateway-config get gateway.providers.0.name --file sentinelguard-gateway.yaml
```

Scanner policy can be changed the same way:

```bash
sentinelguard config set prompt_scanners.secrets.threshold 0.3 --file sentinelguard.yaml
sentinelguard config enable pii --type output --file sentinelguard.yaml
```

## Stable Management API

Use `/gateway/v1` for dashboards and automation:

```bash
curl http://localhost:8080/gateway/v1/contract
curl http://localhost:8080/gateway/v1/health
curl http://localhost:8080/gateway/v1/routes
curl http://localhost:8080/gateway/v1/provider-health
```

## Docker Compose

```bash
sentinelguard init
cp .env.example .env
docker compose -f docker-compose.sentinelguard.yml up --build
```

The generated Dockerfile installs the selected SentinelGuard PyPI version into
a small gateway image.
