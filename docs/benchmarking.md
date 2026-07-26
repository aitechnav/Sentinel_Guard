# Benchmarking

SentinelGuard includes a benchmark harness for testing detection behavior across
prompt attacks, PII, PHI, PCI, and secrets.

## Run Local Benchmarks

```bash
python benchmarks/run.py
```

## Recommended Dataset Strategy

Use synthetic data first for PII, PHI, PCI, and secrets. Avoid putting real
secrets or real personal data into benchmark fixtures.

For prompt-injection coverage, maintain a small CI-safe set and a larger
research set. Track:

- True positives
- False positives
- False negatives
- Latency
- Scanner-level failure reasons

## Why Benchmarks Matter

Security users will ask for evidence. A repeatable benchmark harness makes it
easier to improve detection without relying on anecdotal examples.
