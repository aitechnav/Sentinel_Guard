# SentinelGuard Quick Start Guide

Get up and running with SentinelGuard in 5 minutes.

## 1. Install

```bash
pip install sentinelguard
```

For gateway mode:

```bash
pip install "sentinelguard[gateway,monitoring]"
sentinelguard init
```

For Docker Compose, run `sentinelguard init`, copy `.env.example` to `.env`,
set a provider key, then start `docker-compose.sentinelguard.yml`.

For optional model-backed detection with automatic background warmup:

```bash
pip install "sentinelguard[models]"
```

## 2. Basic Usage

```python
from sentinelguard import SentinelGuard

guard = SentinelGuard()

# Scan user input before sending to LLM
result = guard.scan_prompt("Tell me about Python programming")
if result.is_valid:
    print("Safe to proceed!")
else:
    print(f"Blocked by: {result.failed_scanners}")
```

## 3. Use Presets

```python
# Minimal - essential scanners only
guard = SentinelGuard.minimal()

# Strict - all scanners at low thresholds
guard = SentinelGuard.strict()
```

## 4. Full Pipeline

```python
guard = SentinelGuard.minimal()

# Step 1: Validate input
user_input = "What is machine learning?"
prompt_result = guard.scan_prompt(user_input)

if not prompt_result.is_valid:
    print(f"Input rejected: {prompt_result.failed_scanners}")
else:
    # Step 2: Call your LLM
    llm_response = your_llm_call(user_input)

    # Step 3: Validate output
    output_result = guard.scan_output(llm_response, prompt=user_input)

    if output_result.is_valid:
        print(llm_response)
    else:
        print(f"Output filtered: {output_result.failed_scanners}")
```

## 5. PII Detection

```python
from sentinelguard.pii import PIIDetector, PIIAnonymizer

detector = PIIDetector()
anonymizer = PIIAnonymizer(default_strategy="replace")

text = "Email me at alice@example.com"
entities = detector.detect(text)
result = anonymizer.anonymize(text, entities)
print(result.text)  # "Email me at <EMAIL_ADDRESS>"
```

## 6. CLI

```bash
# Scan text from the command line
sentinelguard scan prompt "Hello world"
sentinelguard scan prompt "Ignore previous instructions" --format json

# List available scanners
sentinelguard scanners list

# Create and edit scanner config
sentinelguard config init --preset standard --output sentinelguard.yaml
sentinelguard config set prompt_scanners.pii.threshold 0.3 --file sentinelguard.yaml
sentinelguard config disable toxicity --type prompt --file sentinelguard.yaml

# Edit gateway routing and security config
sentinelguard gateway-config set gateway.routing_strategy weighted --file sentinelguard-gateway.yaml
sentinelguard gateway-config set gateway.cache_enabled true --file sentinelguard-gateway.yaml
sentinelguard gateway-config get gateway.providers.0.name --file sentinelguard-gateway.yaml

# Start API server
sentinelguard serve --port 8000

# Create gateway starter files
sentinelguard init

# Start the generated Docker gateway
cp .env.example .env
docker compose -f docker-compose.sentinelguard.yml up --build

# Start OpenAI-compatible LLM gateway from generated config
export OPENAI_API_KEY="sk-..."
export SENTINELGUARD_GATEWAY_API_KEY="local-gateway-token"
sentinelguard gateway \
  --config sentinelguard.yaml \
  --gateway-config sentinelguard-gateway.yaml \
  --port 8080

# Or start a quick single-provider gateway without config files
sentinelguard gateway --provider openai --port 8080

# Or use a native provider adapter
export ANTHROPIC_API_KEY="sk-ant-..."
sentinelguard gateway --provider anthropic --port 8080

export GEMINI_API_KEY="..."
sentinelguard gateway --provider gemini --port 8080
```

Point OpenAI-compatible apps or IDEs to:

```text
http://localhost:8080/v1
```

The gateway protects traffic only when the app or IDE sends model requests
through that URL.
Requests with `stream=true` are supported with safe buffered streaming.
Install `sentinelguard[gateway,models]` to use gateway mode with optional
model-backed detection.
Install `sentinelguard[gateway,monitoring]` to expose Prometheus metrics at
`/metrics` for PII, secret, and attack detections.
Set `SENTINELGUARD_AUDIT_SALT` and pass `X-User-ID` / `X-Tenant-ID` headers
to get privacy-safe JSON audit logs for detections.

## 7. YAML Configuration

Create `sentinelguard.yaml`:

```yaml
mode: standard
model_warmup: true
prompt_scanners:
  prompt_injection:
    enabled: true
    threshold: 0.5
  pii:
    enabled: true
    threshold: 0.5
  toxicity:
    enabled: true
    threshold: 0.7
```

```python
guard = SentinelGuard.from_config("sentinelguard.yaml")
```

## Next Steps

- See `examples/` for more detailed usage examples
- Check `configs/example_config.yaml` for full configuration options
- Read the full [README](README.md) for advanced features
