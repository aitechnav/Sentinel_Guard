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
- `SENTINELGUARD_GATEWAY_API_KEY` is the gateway client token created by the
  team running SentinelGuard. Apps, IDEs, and SDKs use this token when calling
  SentinelGuard at `http://localhost:8080/v1`.

This token is separate from upstream provider API keys. Generate it once for
your gateway, then use the same value in both places:

- The SentinelGuard gateway environment, as `SENTINELGUARD_GATEWAY_API_KEY`.
- Your app, SDK, or IDE API-key field when its base URL points to
  `http://localhost:8080/v1`.

After installing SentinelGuard, generate the token with:

```bash
sentinelguard token
```

Or print the shell export command directly:

```bash
sentinelguard token --env
```

If you prefer SentinelGuard to create a local `.env` file for Docker Compose,
use:

```bash
sentinelguard init --with-env
```

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
Copy the generated `sgw_...` value into your app or IDE as the API key. Do not
run `sentinelguard token` again for the app or IDE, because that would create a
different token. In shared or production deployments, keep the token out of
source code.
If you remove `client_api_key_env` and all `virtual_keys` from the gateway YAML,
client-token authentication is disabled; keep it enabled for shared Docker,
Kubernetes, or team gateways.

## Where Keys Are Stored

SentinelGuard does not store generated tokens in a hosted service or hidden
account. The gateway reads secrets from the place you configure:

- Local shell: `export SENTINELGUARD_GATEWAY_API_KEY=...`
- Local Docker Compose: `.env`, generated with `sentinelguard init --with-env`
- Kubernetes: a Kubernetes Secret mounted as environment variables
- Production: your platform secret manager or vault

The gateway YAML usually stores only environment-variable names, not secret
values:

```yaml
gateway:
  api_key_env: OPENAI_API_KEY
  client_api_key_env: SENTINELGUARD_GATEWAY_API_KEY
```

Technically, SentinelGuard also supports putting direct values in YAML:

```yaml
gateway:
  api_key: sk-...
  client_api_key: sgw_...
```

For real use, prefer environment variables, `.env` files that are ignored by
Git, Kubernetes Secrets, or a secret manager. Do not commit real LLM API keys or
gateway tokens into `sentinelguard-gateway.yaml`.

## Admin Dashboard And Per-Client Tokens

SentinelGuard includes its own gateway dashboard at:

```text
http://localhost:8080/admin
```

The dashboard has two roles:

| Role | Access |
| --- | --- |
| `admin` | Read usage, create client tokens, update allowed models and metadata, rotate tokens, and enable or disable managed clients |
| `viewer` | Read usage, provider health, and client status only |

Set dashboard credentials with environment variables:

```bash
export SENTINELGUARD_ADMIN_USERNAME="admin"
export SENTINELGUARD_ADMIN_PASSWORD="use-a-strong-password"
export SENTINELGUARD_VIEWER_USERNAME="viewer"
export SENTINELGUARD_VIEWER_PASSWORD="use-a-readonly-password"
```

If these password variables are not set, SentinelGuard creates local fallback
users for development: `admin` / `sentinelguard` and `viewer` /
`sentinelguard-readonly`. The dashboard shows a warning until real passwords
are configured.

When an admin creates or rotates a client token, SentinelGuard displays the raw
`sgw_...` value once. After that, it stores only a hash and a masked prefix.
The generated token is what a client uses in its API-key field:

```text
Base URL: http://localhost:8080/v1
API key:  generated client token from the dashboard
Model:    sentinel-auto
```

To change the models allowed for an existing dashboard-managed token, select the
client in `/admin`, edit **Allowed models**, and save. For example:
`sentinel-auto, fast-chat, smart-chat, private-chat`. This updates the existing
client token policy; it does not require rotating the token.

A dashboard-managed client can also rotate its own token while it still has a
valid current token:

```bash
curl -X POST http://localhost:8080/gateway/v1/client/token/rotate \
  -H "Authorization: Bearer $SENTINELGUARD_CLIENT_TOKEN"
```

If a client loses its token, an admin should rotate that client from the
dashboard and update the application, IDE, Kubernetes Secret, ECS task secret,
or VM environment variable that uses it.

## Lost Or Rotated Gateway Token

This section applies to CLI-generated or config-managed gateway tokens. For
dashboard-managed clients, rotate the client from `/admin` and update only that
client's app or service secret.

`sentinelguard token` is stateless. It does not look up, refresh, or remember
old tokens. Every time you run it, it prints a new random token.

If you lose the gateway token:

```bash
export SENTINELGUARD_GATEWAY_API_KEY="$(sentinelguard token)"
echo "$SENTINELGUARD_GATEWAY_API_KEY"
```

Then restart the SentinelGuard gateway and update every app, SDK, or IDE that
uses the gateway so its API key matches the new `sgw_...` value.

The old token will stop working unless it is still configured on the running
gateway. For planned rotation, keep both old and new tokens temporarily by
configuring two virtual keys:

```yaml
gateway:
  virtual_keys:
    - name: current
      key_env: SENTINELGUARD_GATEWAY_API_KEY
      allowed_models: ["*"]
    - name: previous
      key_env: SENTINELGUARD_GATEWAY_API_KEY_OLD
      allowed_models: ["*"]
```

After clients move to the new token, remove the old virtual key and restart the
gateway again. For Docker or Kubernetes, update the Secret or `.env` value and
restart the container or pod.


## Named Guardrails And Sensitive Routing

Gateway guardrails can be named so teams can expose a stable policy contract to
apps, IDEs, benchmark jobs, and dashboards. If no custom guardrails are
configured, SentinelGuard uses the default scanner policy.

```yaml
gateway:
  guardrails:
    - name: privacy
      mode: enforce
      stages: [pre_call, post_call, passthrough]
      directions: [prompt, output]
      description: PII, secret, and prompt-security enforcement

  default_guardrail_names: [privacy]
  route_sensitive_to_private_provider: true
  sensitive_session_routing_enabled: true
  sensitive_session_ttl_seconds: 1800
```

When sticky sensitive-session routing is enabled, SentinelGuard can keep a
conversation on a private provider after PII or secrets are detected. Clients can
provide `X-SentinelGuard-Session-ID`, `X-Session-ID`, or `X-Conversation-ID` so
only that conversation is pinned instead of the whole client token.

To scan text without calling an LLM provider, use the stable apply endpoint:

```bash
curl http://localhost:8080/gateway/v1/guardrails/apply \
  -H "Authorization: Bearer $SENTINELGUARD_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"input":"Contact Alice at alice@example.com","direction":"prompt"}'
```

The response contains the final action, named guardrail decisions, scanner
summary, and sanitized text when available.

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

## Automatic Model Routing

SentinelGuard supports gateway-side routing in three practical layers:

| Routing type | Status | How to use it |
| --- | --- | --- |
| Rule-based routing | Supported | Use `complexity_router` with `sentinel-auto` to send simple prompts to a lower-cost route and complex prompts to a stronger route. |
| Cost-aware routing | Supported | Use `routing_strategy: cost-based-routing` inside a provider pool serving the same model alias. |
| LLM-based routing | Not enabled by default | Keep this as an optional future mode when you want a separate router model; rule-based routing is faster and safer for the default gateway path. |

The generated gateway config exposes these friendly model names:

- `sentinel-auto`: SentinelGuard chooses the route.
- `fast-chat`: lower-cost route for simple prompts.
- `smart-chat`: stronger route for complex prompts.
- `private-chat`: local/private route for sensitive traffic when private routing is enabled.

Example:

```yaml
gateway:
  route_pii_to_private_provider: true
  routing_strategy: cost-based-routing
  complexity_router:
    enabled: true
    strategy: rule-based
    auto_model_names:
      - sentinel-auto
      - auto
    simple_model: fast-chat
    complex_model: smart-chat
    private_model: private-chat
    preserve_explicit_model: true
    complexity_threshold: 0.65

  providers:
    - name: openai-fast
      provider: openai
      model_name: fast-chat
      upstream_model: gpt-4o-mini
      input_cost_per_token: 0.00000015
      output_cost_per_token: 0.0000006

    - name: openai-smart
      provider: openai
      model_name: smart-chat
      upstream_model: gpt-4o
      input_cost_per_token: 0.000003
      output_cost_per_token: 0.000015

    - name: ollama-private
      provider: ollama
      model_name: private-chat
      upstream_model: llama3.1
      private: true
```

Apps and IDEs can then use:

```text
Base URL: http://localhost:8080/v1
API key:  the same sgw_... value from SENTINELGUARD_GATEWAY_API_KEY
Model:    sentinel-auto
```

With `preserve_explicit_model: true`, SentinelGuard only auto-routes requests
whose model is one of `auto_model_names`. If a client explicitly requests
`fast-chat` or `smart-chat`, SentinelGuard keeps that route. Set
`preserve_explicit_model: false` only when you want the gateway to override
client-selected model names.

## Configure Apps And IDEs

Use this OpenAI-compatible base URL:

```text
http://localhost:8080/v1
```

If gateway client authentication is enabled, use the configured gateway token as
the client API key. That value is your `SENTINELGUARD_GATEWAY_API_KEY`, not the
upstream provider key.

For OpenAI SDK-compatible settings, this usually means:

```text
Base URL: http://localhost:8080/v1
API key:  the same sgw_... value from SENTINELGUARD_GATEWAY_API_KEY
```

The purpose of this token is to protect the gateway endpoint. Without it,
anyone who can reach the gateway could indirectly use the upstream provider key
stored on the gateway process.

For EKS, EC2, Docker Compose, SDK, IDE, and browser-chat integration examples,
see [Client Integration Patterns](client-integrations.md).

For an application that uses the OpenAI SDK, the app uses the gateway URL and
the SentinelGuard gateway token:

```bash
export OPENAI_BASE_URL="http://localhost:8080/v1"
export OPENAI_API_KEY="$SENTINELGUARD_GATEWAY_API_KEY"
```

In this app environment, `OPENAI_API_KEY` is intentionally the SentinelGuard
gateway token because the app is authenticating to SentinelGuard. The real
upstream provider key, such as `sk-...`, stays only on the SentinelGuard
gateway process.

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
