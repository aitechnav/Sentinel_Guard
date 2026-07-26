# LLM Gateway

Gateway mode lets SentinelGuard run as a separate proxy in front of model
providers. Applications, SDKs, and IDEs send OpenAI-compatible traffic to
SentinelGuard first.

```text
Application or IDE
  -> SentinelGuard /v1/chat/completions
  -> OpenAI, Anthropic, Gemini, Kimi, Ollama, Mistral, DeepSeek, or another provider
```

## Start Locally

The example below uses two different keys:

- `OPENAI_API_KEY` is the upstream provider key used by SentinelGuard to call OpenAI.
- `SENTINELGUARD_GATEWAY_API_KEY` is a client-facing token that you generate. Your
  apps, IDEs, and SDKs use this token when calling SentinelGuard at
  `http://localhost:8080/v1`.

```bash
pip install "sentinelguard[gateway,monitoring]"
export OPENAI_API_KEY="sk-..."
export SENTINELGUARD_GATEWAY_API_KEY="$(sentinelguard token)"

sentinelguard init
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080
```

For local testing, `sentinelguard token` generates a secure random local token.
In shared or production deployments, keep that value out of source code.
If you remove `client_api_key_env` and all `virtual_keys` from the gateway YAML,
client-token authentication is disabled; keep it enabled for shared Docker,
Kubernetes, or team gateways.

## Supported Providers

SentinelGuard can run as one gateway in front of public, private, and local
model providers:

| Provider | CLI shortcut | Key environment variable |
| --- | --- | --- |
| OpenAI | `--provider openai` | `OPENAI_API_KEY` |
| Anthropic Claude | `--provider anthropic` | `ANTHROPIC_API_KEY` |
| Google Gemini | `--provider gemini` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` |
| Kimi / Moonshot | `--provider kimi` | `MOONSHOT_API_KEY` or `KIMI_API_KEY` |
| DeepSeek | `--provider deepseek` | `DEEPSEEK_API_KEY` |
| Mistral | `--provider mistral` | `MISTRAL_API_KEY` |
| MiniMax | `--provider minimax` | `MINIMAX_API_KEY` |
| Ollama | `--provider ollama` | optional `OLLAMA_API_KEY` |
| Hugging Face router | `--provider huggingface` | `HF_TOKEN` or `HUGGINGFACE_API_KEY` |
| vLLM, TGI, llama.cpp, private gateways | `--provider openai-compatible` | your configured key env |

Examples:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
sentinelguard gateway --provider anthropic --port 8080

export GEMINI_API_KEY="..."
sentinelguard gateway --provider gemini --port 8080

export MOONSHOT_API_KEY="..."
sentinelguard gateway --provider kimi --port 8080
```

## Configure Apps And IDEs

Use this OpenAI-compatible base URL:

```text
http://localhost:8080/v1
```

If gateway client authentication is enabled, use the configured gateway token as
the client API key. That value is your `SENTINELGUARD_GATEWAY_API_KEY`, not the
upstream provider key.

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
sentinelguard init --with-env
# Edit .env and set at least one upstream provider key, such as OPENAI_API_KEY.
docker compose -f docker-compose.sentinelguard.yml up --build
```

The generated Dockerfile installs the selected SentinelGuard PyPI version into
a small gateway image.
