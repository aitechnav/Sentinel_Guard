# Contributing

Thanks for helping improve SentinelGuard. Contributions can be code, tests,
benchmark cases, docs, examples, issue reports, deployment recipes, or security
review.

## Good First Contributions

- Add labeled benchmark cases for prompt injection, PII, PCI, PHI, secrets, or
  benign negatives.
- Improve examples for Docker, Kubernetes, ECS, EC2, IDEs, or SDK clients.
- Add provider configuration examples for OpenAI-compatible model servers.
- Improve scanner docs with realistic safe test cases.
- Add focused tests around a bug or behavior change.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,gateway,monitoring]"
```

Optional model-backed scanner work:

```bash
pip install -e ".[dev,gateway,monitoring,models]"
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
ruff check sentinelguard tests examples/test_apps/gateway_test_client.py
pytest
```

For focused gateway work:

```bash
pytest tests/test_gateway.py tests/test_cli.py
```

For docs:

```bash
pip install -r requirements-docs.txt
mkdocs build --strict
```

## Contribution Workflow

1. Open an issue or describe the problem in the pull request.
2. Keep changes focused. Avoid unrelated formatting churn.
3. Add or update tests for behavior changes.
4. Update docs and examples when user-facing behavior changes.
5. Run the relevant checks before opening the pull request.
6. Include screenshots or command output when changing docs, CLI output, or UI
   behavior.

## Security And Test Data

- Do not commit real API keys, tokens, credentials, PHI, PCI data, or personal
  information.
- Use synthetic examples for secrets, PII, PCI, and PHI.
- If a test needs token-shaped strings, make sure they are fake and documented
  as fake.
- For vulnerability reports, follow [SECURITY.md](SECURITY.md) instead of
  opening a detailed public issue.

## Documentation Style

Keep docs practical:

- install
- configure
- run
- verify
- troubleshoot

Prefer examples users can copy into local development, Docker, Kubernetes, EKS,
ECS, EC2, or an OpenAI-compatible SDK client.

## License

By contributing, you agree that your contribution will be licensed under the
Apache License 2.0 used by this project.
