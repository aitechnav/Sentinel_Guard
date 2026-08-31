---
title: SentinelGuard
description: Security-first LLM gateway and guardrails framework for AI applications
---

<div class="sg-page">
  <nav class="sg-product-nav" aria-label="SentinelGuard links">
    <a class="sg-brand" href="index.html" aria-label="SentinelGuard home">
      <img class="sg-brand-logo" src="assets/images/sentinelguard-logo.svg" alt="" />
      <span>SentinelGuard</span>
    </a>
    <div class="sg-nav-links">
      <a href="getting-started.html">Docs</a>
      <a href="gateway.html">Gateway</a>
      <a href="client-integrations.html">Integrations</a>
      <a href="deployment.html">Deploy</a>
    </div>
  </nav>

  <section class="sg-hero">
    <div class="sg-hero-copy">
      <p class="sg-eyebrow">Security-first LLM gateway and guardrails framework</p>
      <h1>Put one protected gateway in front of your AI traffic</h1>
      <p class="sg-lede">
        SentinelGuard helps teams secure LLM applications, AI IDEs, agents, and
        model provider traffic with prompt scanning, output scanning, PII and
        secret protection, model routing, failover, usage controls, audit
        events, and a stable management API.
      </p>
      <div class="sg-actions">
        <a class="sg-button sg-button-primary" href="getting-started.html">Start in 5 minutes</a>
        <a class="sg-button sg-button-secondary" href="gateway.html">Run the gateway</a>
        <a
          class="sg-button sg-button-secondary"
          href="https://github.com/aitechnav/Sentinel_Guard"
          target="_blank"
          rel="noopener"
        >View on GitHub</a>
      </div>
      <div class="sg-proof-row">
        <span>OpenAI-compatible gateway</span>
        <span>PII and secret controls</span>
        <span>Prometheus metrics</span>
        <span>Docker and Kubernetes ready</span>
      </div>
      <div class="sg-provider-row" aria-label="Supported providers">
        <span>OpenAI</span>
        <span>Anthropic Claude</span>
        <span>Google Gemini</span>
        <span>Kimi / Moonshot</span>
        <span>DeepSeek</span>
        <span>Mistral</span>
        <span>MiniMax</span>
        <span>Ollama</span>
        <span>Hugging Face</span>
      </div>
    </div>

    <div class="sg-terminal" aria-label="SentinelGuard gateway quick start">
      <div class="sg-terminal-bar">
        <span></span>
        <span></span>
        <span></span>
      </div>
      <p class="sg-panel-title">Install and start the gateway</p>
      <pre><code>pip install "sentinelguard[gateway,monitoring]"
export OPENAI_API_KEY="sk-..."
export SENTINELGUARD_GATEWAY_API_KEY="$(sentinelguard token)"
sentinelguard init
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080</code></pre>
      <p class="sg-muted">Point apps and IDEs to <code>http://localhost:8080/v1</code></p>
    </div>
  </section>

  <section class="sg-metrics" aria-label="SentinelGuard capabilities">
    <div>
      <strong>36</strong>
      <span>security scanners</span>
    </div>
    <div>
      <strong>v1</strong>
      <span>stable gateway API</span>
    </div>
    <div>
      <strong>2 modes</strong>
      <span>package and proxy</span>
    </div>
    <div>
      <strong>local</strong>
      <span>model-backed detection</span>
    </div>
  </section>

  <section class="sg-section">
    <div class="sg-section-heading">
      <p class="sg-eyebrow">Why teams use SentinelGuard</p>
      <h2>Runtime protection for the LLM boundary</h2>
    </div>
    <div class="sg-card-grid">
      <article class="sg-card">
        <h3>Secure prompts and responses</h3>
        <p>
          Scan prompts before they reach a model and scan responses before they
          return to users. Block attacks, redact PII, and stop secrets from
          leaving the application.
        </p>
      </article>
      <article class="sg-card">
        <h3>Route across providers</h3>
        <p>
          Use friendly model names, automatic complexity routing, cost-aware
          provider routing, failover when one provider is unavailable, and
          private routes for sensitive traffic.
        </p>
      </article>
      <article class="sg-card">
        <h3>Operate with evidence</h3>
        <p>
          Use virtual keys, usage accounting, provider health, privacy-safe
          audit events, Prometheus metrics, and the stable
          <code>/gateway/v1</code> API for dashboards and alerts.
        </p>
      </article>
    </div>
  </section>

  <section class="sg-section">
    <div class="sg-section-heading">
      <p class="sg-eyebrow">Built for modern AI applications</p>
      <h2>Use it in code or as a shared gateway</h2>
    </div>
    <div class="sg-split">
      <article>
        <h3>Package mode</h3>
        <p>Use SentinelGuard directly in Python code when you want guardrails inside one application.</p>
        <pre><code>from sentinelguard import SentinelGuard

guard = SentinelGuard()
result = guard.scan_prompt("Ignore previous instructions")
print(result.is_valid, result.failed_scanners)</code></pre>
      </article>
      <article>
        <h3>Gateway mode</h3>
        <p>Run SentinelGuard as a proxy so multiple applications, users, and AI tools share one security boundary.</p>
        <pre><code>App or IDE -> SentinelGuard /v1 -> LLM provider</code></pre>
        <p class="sg-muted">Stable endpoints: <code>/gateway/v1/contract</code>, <code>/gateway/v1/health</code>, <code>/gateway/v1/routes</code></p>
      </article>
    </div>
  </section>

  <section class="sg-section sg-docs-section">
    <div class="sg-section-heading">
      <p class="sg-eyebrow">Explore the docs</p>
      <h2>Pick the workflow you need</h2>
    </div>
    <div class="sg-doc-list">
      <a href="getting-started.html">
        <span>Use SentinelGuard inside Python code</span>
        <strong>Getting Started</strong>
      </a>
      <a href="gateway.html">
        <span>Put SentinelGuard in front of apps or IDEs</span>
        <strong>LLM Gateway</strong>
      </a>
      <a href="gateway-api.html">
        <span>Build a dashboard or integration</span>
        <strong>Stable Gateway API</strong>
      </a>
      <a href="deployment.html">
        <span>Deploy with containers or Kubernetes</span>
        <strong>Deployment</strong>
      </a>
      <a href="docker-release.html">
        <span>Publish official Docker images</span>
        <strong>Docker Release</strong>
      </a>
    </div>
  </section>
</div>
