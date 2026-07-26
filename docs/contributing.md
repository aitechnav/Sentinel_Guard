# Contributing

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,gateway,monitoring]"
```

## Run Checks

```bash
ruff check sentinelguard tests
pytest
```

## Build Docs Locally

```bash
pip install -r requirements-docs.txt
mkdocs serve
```

Then open:

```text
http://127.0.0.1:8000
```

## Documentation Style

Keep docs focused on practical tasks:

- Install
- Configure
- Run
- Verify
- Troubleshoot

Prefer examples that users can copy into local development, Docker, or
Kubernetes environments.
