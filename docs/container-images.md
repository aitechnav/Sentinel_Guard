# Container Images

SentinelGuard can run as a containerized LLM gateway in front of OpenAI,
Anthropic, Gemini, DeepSeek, Mistral, MiniMax, Kimi/Moonshot, Ollama,
Hugging Face, and other OpenAI-compatible providers.

## Images

Published images are intended to be pulled by applications, platform teams,
and Kubernetes deployments.

```text
ghcr.io/<github-owner>/sentinelguard-gateway:<version>
ghcr.io/<github-owner>/sentinelguard-gateway:latest
aitechnav/sentinelguard:<version>
aitechnav/sentinelguard:latest
```

Use a version tag for production deployments so upgrades are explicit.
Use `latest` only for local testing or demos.

## Run Locally

```bash
docker run --rm -p 8080:8080 \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e SENTINELGUARD_GATEWAY_API_KEY="$SENTINELGUARD_GATEWAY_API_KEY" \
  aitechnav/sentinelguard:0.0.14
```

Then point OpenAI-compatible clients to:

```text
Base URL: http://localhost:8080/v1
API key:  your SentinelGuard gateway client token
```

## Docker Compose And Kubernetes

For local multi-container testing, use the repository `docker-compose.yml`.
For Kubernetes, use `examples/kubernetes` or the Helm chart under
`examples/helm/sentinelguard`.

The gateway should receive upstream provider keys through environment
variables, Kubernetes Secrets, ECS task secrets, or your platform secret
manager. Client apps and IDEs should receive only the SentinelGuard gateway
token, not the upstream provider key.

## Supply Chain Metadata

Release images may include SBOM, provenance, and signature metadata so
security teams can verify where the image came from and inspect its package
contents. Exact verification commands depend on the registry and release tag
your organization uses.
