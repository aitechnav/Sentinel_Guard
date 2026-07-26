# SentinelGuard

<div class="sg-hero" markdown>
<div markdown>

<p class="sg-eyebrow">Security-first LLM gateway and guardrails framework</p>

## Put one protected gateway in front of your AI traffic

SentinelGuard helps teams secure LLM applications, AI IDEs, agents, and model
provider traffic with prompt scanning, output scanning, PII and secret
protection, model routing, failover, usage controls, audit events, and a stable
management API.

<div class="sg-actions" markdown>
[Start in 5 minutes](getting-started.md){ .sg-button .sg-button-primary }
[Run the gateway](gateway.md){ .sg-button .sg-button-secondary }
[View on GitHub](https://github.com/aitechnav/Sentinel_Guard){ .sg-button .sg-button-secondary target="_blank" }
</div>

<div class="sg-proof-row" markdown>
<span>OpenAI-compatible gateway</span>
<span>PII and secret controls</span>
<span>Prometheus metrics</span>
<span>Docker and Kubernetes ready</span>
</div>

</div>
<div class="sg-panel" markdown>

<p class="sg-panel-title">Install and start the gateway</p>

```bash
pip install "sentinelguard[gateway,monitoring]"
sentinelguard init
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080
```

Point apps and IDEs to:

```text
http://localhost:8080/v1
```

</div>
</div>

## Why Teams Use SentinelGuard

<div class="sg-card-grid" markdown>
<div class="sg-card" markdown>
### Secure the LLM boundary
Scan prompts before they reach a model and scan responses before they return to
users. Block attacks, redact PII, and stop secrets from leaving the application.
</div>

<div class="sg-card" markdown>
### Route across providers
Use friendly model names, route traffic across OpenAI-compatible providers,
fail over when one provider is unavailable, and keep private routes available
for sensitive traffic.
</div>

<div class="sg-card" markdown>
### Operate with evidence
Use virtual keys, usage accounting, provider health, privacy-safe audit events,
Prometheus metrics, and the stable `/gateway/v1` API for dashboards and alerts.
</div>
</div>

## Built For Modern AI Applications

<div class="sg-split" markdown>
<div markdown>

### Package mode

Use SentinelGuard directly in Python code when you want guardrails inside one
application.

```python
from sentinelguard import SentinelGuard

guard = SentinelGuard()
result = guard.scan_prompt("Ignore previous instructions")
print(result.is_valid, result.failed_scanners)
```

</div>
<div markdown>

### Gateway mode

Run SentinelGuard as a proxy so multiple applications, users, and AI tools can
share the same security boundary.

```text
App or IDE -> SentinelGuard /v1 -> LLM provider
```

Stable management API:

```text
/gateway/v1/contract
/gateway/v1/health
/gateway/v1/routes
```

</div>
</div>

## Explore The Docs

| Workflow | Start Here |
| --- | --- |
| Use SentinelGuard inside Python code | [Getting Started](getting-started.md) |
| Put SentinelGuard in front of apps or IDEs | [LLM Gateway](gateway.md) |
| Build a dashboard or integration | [Stable Gateway API](gateway-api.md) |
| Deploy with containers or Kubernetes | [Deployment](deployment.md) |
| Publish official Docker images | [Docker Release](docker-release.md) |

## Open Source And Easy To Try

The GitHub star button in the top-right header shows the repository star count
and opens GitHub's authenticated star flow. GitHub requires the user to be
signed in before starring a repository.
