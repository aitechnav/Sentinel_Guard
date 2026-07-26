# SentinelGuard Gateway API

SentinelGuard has two API surfaces:

- OpenAI-compatible runtime traffic under `/v1`
- SentinelGuard management and observability APIs under `/gateway/v1`

The `/gateway/v1` management API is the stable contract for dashboards,
automation, health checks, and operational integrations. Existing unversioned
management endpoints remain available as compatibility aliases.

## Stable Management Endpoints

```text
GET /gateway/v1
GET /gateway/v1/contract
GET /gateway/v1/health
GET /gateway/v1/routes
GET /gateway/v1/models
GET /gateway/v1/usage
GET /gateway/v1/provider-health
```

`/gateway/v1/contract` returns the current stable contract:

```json
{
  "object": "sentinelguard.gateway.contract",
  "gateway": "sentinelguard",
  "api_version": "v1",
  "stability": "stable",
  "base_path": "/gateway/v1",
  "openai_base_path": "/v1"
}
```

## OpenAI-Compatible Runtime Endpoints

```text
POST /v1/chat/completions
GET /v1/models
```

Applications, SDKs, and IDEs should use `/v1` as the OpenAI-compatible base URL:

```text
http://localhost:8080/v1
```

## Compatibility Aliases

These older paths remain available, but new dashboards and integrations should
prefer `/gateway/v1`.

```text
GET /health
GET /gateway/health
GET /routes
GET /models
GET /gateway/usage
GET /gateway/provider-health
```

## Authentication

Runtime traffic and usage endpoints use the gateway client key when configured.
This is the token you set with `SENTINELGUARD_GATEWAY_API_KEY`; it is separate
from upstream provider keys such as `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
Supported client headers:

```text
Authorization: Bearer <token>
X-API-Key: <token>
X-SentinelGuard-API-Key: <token>
```

`GET /gateway/v1/usage` requires an authenticated gateway client because usage
is scoped to the client or virtual key.

## Stability Rule

Within `/gateway/v1`, response fields may receive additive fields over time.
Existing field names and meanings should not be removed or changed without a
new versioned base path such as `/gateway/v2`.
