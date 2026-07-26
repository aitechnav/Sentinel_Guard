# Security Scanners

SentinelGuard includes prompt and output scanners for common LLM application
risks.

## Prompt Scanners

Examples include:

- Prompt injection
- Jailbreak attempts
- PII
- Secrets and credentials
- Invisible text
- Toxicity
- Token limits
- Supply-chain and data-poisoning patterns

## Output Scanners

Examples include:

- Sensitive information disclosure
- Data leakage
- System prompt leakage
- Output sanitization issues
- Malicious URLs
- Excessive agency
- Bias and misinformation checks

## Model-Backed Detection

Optional local Hugging Face models can add signal for ambiguous prompt attacks
and contextual secret disclosure. Model weights are downloaded to the local
cache when first used.

```bash
pip install "sentinelguard[models]"
```

Use model-backed detection when stronger detection is more important than the
extra local disk and startup cost.
