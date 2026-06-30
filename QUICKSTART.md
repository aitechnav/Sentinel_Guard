# SentinelGuard Quick Start Guide

Get up and running with SentinelGuard in 5 minutes.

## 1. Install

```bash
pip install sentinelguard
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

# Start API server
sentinelguard serve --port 8000

# Start OpenAI-compatible LLM gateway
export OPENAI_API_KEY="sk-..."
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

## 7. YAML Configuration

Create `sentinelguard.yaml`:

```yaml
mode: standard
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
