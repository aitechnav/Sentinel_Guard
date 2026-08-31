# Contributing

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,gateway,monitoring]"
```

## Optional Node Tooling

SentinelGuard is a Python/FastAPI project and does not require Node.js for the
current gateway or documentation flow. If future dashboard or frontend tooling
is added, use Node.js 24. The repo pins this with `.nvmrc` and `.node-version`.

```bash
nvm use
node --version
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
