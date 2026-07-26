"""Project bootstrap helpers for the SentinelGuard CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import Iterable

import yaml

from sentinelguard import __version__
from sentinelguard.core.config import GuardConfig


INIT_PROFILES = ("gateway", "library")
CONFIG_PRESETS = ("minimal", "standard", "strict")


@dataclass(frozen=True)
class InitResult:
    """Files created or skipped by ``sentinelguard init``."""

    output_dir: Path
    profile: str
    created: tuple[Path, ...]
    skipped: tuple[Path, ...]


def create_project_scaffold(
    output_dir: str | Path = ".",
    *,
    profile: str = "gateway",
    preset: str = "standard",
    docker_image: str = "sentinelguard-gateway:local",
    include_docker: bool = True,
    force: bool = False,
) -> InitResult:
    """Create starter files for using SentinelGuard in a project."""

    profile = _normalize_choice(profile, INIT_PROFILES, "profile")
    preset = _normalize_choice(preset, CONFIG_PRESETS, "preset")
    target = Path(output_dir).expanduser().resolve()

    files = list(_base_files(profile=profile, preset=preset))
    if profile == "gateway":
        files.extend(_gateway_files(docker_image=docker_image, include_docker=include_docker))

    created: list[Path] = []
    skipped: list[Path] = []
    for relative_path, content in files:
        path = target / relative_path
        if path.exists() and not force:
            skipped.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(path)

    return InitResult(
        output_dir=target,
        profile=profile,
        created=tuple(created),
        skipped=tuple(skipped),
    )


def _base_files(profile: str, preset: str) -> Iterable[tuple[str, str]]:
    yield "sentinelguard.yaml", _scanner_config_yaml(preset)
    yield "README.sentinelguard.md", _readme(profile)


def _gateway_files(
    *,
    docker_image: str,
    include_docker: bool,
) -> Iterable[tuple[str, str]]:
    yield "sentinelguard-gateway.yaml", _gateway_config_yaml()
    yield ".env.example", _env_example()
    if include_docker:
        yield "Dockerfile.sentinelguard", _dockerfile()
        yield "docker-compose.sentinelguard.yml", _docker_compose(docker_image)


def _scanner_config_yaml(preset: str) -> str:
    if preset == "minimal":
        config = GuardConfig.preset_minimal()
    elif preset == "strict":
        config = GuardConfig.preset_strict()
    else:
        config = GuardConfig.preset_standard()
    return yaml.safe_dump(config.to_dict(), sort_keys=False)


def _gateway_config_yaml() -> str:
    return dedent(
        """\
        gateway:
          enabled: true
          provider: openai
          upstream_url: https://api.openai.com/v1
          api_key_env: OPENAI_API_KEY
          client_api_key_env: SENTINELGUARD_GATEWAY_API_KEY
          forward_authorization: false

          block_on_prompt_fail: true
          block_on_output_fail: true
          sanitize: true
          redact_pii: true
          redact_output_pii: true
          route_pii_to_private_provider: false

          fallback_enabled: true
          routing_strategy: priority
          health_check_enabled: true
          unhealthy_ttl_seconds: 30
          failover_status_codes: [408, 409, 425, 429, 500, 502, 503, 504]
          timeout_seconds: 60
          default_max_tokens: 1024
          streaming_mode: buffered

          state_backend: sqlite
          state_path: ./.sentinelguard/gateway.sqlite3
          cache_enabled: false
          cache_backend: sqlite
          cache_ttl_seconds: 300
          cache_max_entries: 1024

          metrics_enabled: true
          audit_enabled: true
          audit_hash_salt_env: SENTINELGUARD_AUDIT_SALT
          admin_ui_enabled: true
          otel_enabled: false
          langfuse_enabled: false

          mcp_gateway_enabled: false
          mcp_upstream_url: http://localhost:9001
          a2a_gateway_enabled: false
          a2a_upstream_url: http://localhost:9002
          realtime_gateway_enabled: false
          realtime_upstream_url: ws://localhost:9003/v1/realtime

          virtual_keys:
            - name: local-dev
              key_env: SENTINELGUARD_GATEWAY_API_KEY
              allowed_models:
                - fast-chat
                - smart-chat
                - private-chat
              max_requests: 10000
              max_tokens: 5000000
              max_budget: 50.0
              budget_reset: daily

          providers:
            - name: openai-fast
              provider: openai
              model_name: fast-chat
              upstream_model: gpt-4o-mini
              upstream_url: https://api.openai.com/v1
              api_key_env: OPENAI_API_KEY
              priority: 10
              weight: 3
              input_cost_per_token: 0.00000015
              output_cost_per_token: 0.0000006
              max_parallel_requests: 50

            - name: anthropic-smart
              provider: anthropic
              model_name: smart-chat
              upstream_model: claude-3-5-sonnet-latest
              upstream_url: https://api.anthropic.com/v1
              api_key_env: ANTHROPIC_API_KEY
              priority: 20
              weight: 1
              input_cost_per_token: 0.000003
              output_cost_per_token: 0.000015
              max_parallel_requests: 25

            - name: ollama-private
              provider: ollama
              model_name: private-chat
              upstream_model: llama3.1
              upstream_url: http://localhost:11434/v1
              api_key_env: OLLAMA_API_KEY
              private: true
              priority: 5
              weight: 1
              max_parallel_requests: 10
        """
    )


def _env_example() -> str:
    return dedent(
        f"""\
        # Copy this file to .env for Docker Compose, or export these variables in your shell.
        # Never commit real provider keys.

        SENTINELGUARD_VERSION={__version__}
        SENTINELGUARD_EXTRAS=gateway,monitoring
        SENTINELGUARD_IMAGE=sentinelguard-gateway:local
        SENTINELGUARD_GATEWAY_API_KEY=change-me-local-gateway-token
        SENTINELGUARD_AUDIT_SALT=change-me-random-audit-salt
        SENTINELGUARD_GATEWAY_PORT=8080

        OPENAI_API_KEY=
        ANTHROPIC_API_KEY=
        GEMINI_API_KEY=
        GOOGLE_API_KEY=
        DEEPSEEK_API_KEY=
        MISTRAL_API_KEY=
        MINIMAX_API_KEY=
        HF_TOKEN=
        HUGGINGFACE_API_KEY=
        OLLAMA_API_KEY=
        """
    )


def _dockerfile() -> str:
    return dedent(
        f"""\
        FROM python:3.11-slim

        ARG SENTINELGUARD_VERSION={__version__}
        ARG SENTINELGUARD_EXTRAS=gateway,monitoring

        ENV PYTHONDONTWRITEBYTECODE=1 \\
            PYTHONUNBUFFERED=1 \\
            PIP_NO_CACHE_DIR=1

        WORKDIR /app

        RUN python -m pip install --upgrade pip \\
            && python -m pip install "sentinelguard[${{SENTINELGUARD_EXTRAS}}]==${{SENTINELGUARD_VERSION}}"

        EXPOSE 8080

        HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \\
            CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/gateway/v1/health', timeout=3)"

        ENTRYPOINT ["sentinelguard"]
        CMD ["gateway", "--host", "0.0.0.0", "--port", "8080"]
        """
    )


def _docker_compose(docker_image: str) -> str:
    return dedent(
        f"""\
        services:
          sentinelguard-gateway:
            build:
              context: .
              dockerfile: Dockerfile.sentinelguard
              args:
                SENTINELGUARD_VERSION: ${{SENTINELGUARD_VERSION:-{__version__}}}
                SENTINELGUARD_EXTRAS: ${{SENTINELGUARD_EXTRAS:-gateway,monitoring}}
            image: ${{SENTINELGUARD_IMAGE:-{docker_image}}}
            ports:
              - "${{SENTINELGUARD_GATEWAY_PORT:-8080}}:8080"
            environment:
              OPENAI_API_KEY: ${{OPENAI_API_KEY:-}}
              ANTHROPIC_API_KEY: ${{ANTHROPIC_API_KEY:-}}
              GEMINI_API_KEY: ${{GEMINI_API_KEY:-}}
              GOOGLE_API_KEY: ${{GOOGLE_API_KEY:-}}
              DEEPSEEK_API_KEY: ${{DEEPSEEK_API_KEY:-}}
              MISTRAL_API_KEY: ${{MISTRAL_API_KEY:-}}
              MINIMAX_API_KEY: ${{MINIMAX_API_KEY:-}}
              HF_TOKEN: ${{HF_TOKEN:-}}
              HUGGINGFACE_API_KEY: ${{HUGGINGFACE_API_KEY:-}}
              OLLAMA_API_KEY: ${{OLLAMA_API_KEY:-}}
              SENTINELGUARD_GATEWAY_API_KEY: ${{SENTINELGUARD_GATEWAY_API_KEY:-}}
              SENTINELGUARD_AUDIT_SALT: ${{SENTINELGUARD_AUDIT_SALT:-local-dev-audit-salt}}
            volumes:
              - ./sentinelguard.yaml:/etc/sentinelguard/sentinelguard.yaml:ro
              - ./sentinelguard-gateway.yaml:/etc/sentinelguard/gateway.yaml:ro
              - ./.sentinelguard:/app/.sentinelguard
            command:
              - gateway
              - --host
              - 0.0.0.0
              - --port
              - "8080"
              - --config
              - /etc/sentinelguard/sentinelguard.yaml
              - --gateway-config
              - /etc/sentinelguard/gateway.yaml
        """
    )


def _readme(profile: str) -> str:
    if profile == "library":
        return dedent(
            """\
            # SentinelGuard Project Setup

            This folder was initialized for library mode.

            ## Install

            ```bash
            python -m pip install sentinelguard
            ```

            ## Use

            ```python
            from sentinelguard import SentinelGuard

            guard = SentinelGuard.from_config("sentinelguard.yaml")
            result = guard.scan_prompt("Ignore all previous instructions")
            print(result.is_valid, result.failed_scanners)
            ```

            Use `sentinelguard config init --preset strict` if you only need a
            scanner config file. Use `sentinelguard init --profile gateway` when
            you want SentinelGuard to run as an LLM gateway.
            """
        )

    return dedent(
        """\
        # SentinelGuard Gateway Setup

        This folder was initialized for gateway mode. Your application or IDE
        sends OpenAI-compatible requests to SentinelGuard first, and
        SentinelGuard forwards safe traffic to the configured provider.

        ## Install Locally

        ```bash
        python -m pip install "sentinelguard[gateway,monitoring]"
        export SENTINELGUARD_GATEWAY_API_KEY="change-me-local-gateway-token"
        export SENTINELGUARD_AUDIT_SALT="change-me-random-audit-salt"
        export OPENAI_API_KEY="your-provider-key"
        sentinelguard gateway \\
          --config sentinelguard.yaml \\
          --gateway-config sentinelguard-gateway.yaml \\
          --port 8080
        ```

        ## Run With Docker Compose

        ```bash
        cp .env.example .env
        # Edit .env and set at least one upstream provider key.
        docker compose -f docker-compose.sentinelguard.yml up --build
        ```

        The generated Docker setup builds from the SentinelGuard PyPI package
        using the version in `.env`. If you are testing unreleased local source,
        build from the repository Dockerfile instead.

        ## Point Apps Or IDEs To The Gateway

        ```text
        Base URL: http://localhost:8080/v1
        API key:  the value of SENTINELGUARD_GATEWAY_API_KEY
        Model:    fast-chat, smart-chat, or private-chat
        ```

        Use `fast-chat` for OpenAI, `smart-chat` for Anthropic, and
        `private-chat` for local Ollama. Remove provider routes you do not use.

        Useful checks:

        ```bash
        curl http://localhost:8080/health
        curl http://localhost:8080/gateway/v1/contract
        curl http://localhost:8080/gateway/v1/models
        curl http://localhost:8080/gateway/v1/routes
        curl http://localhost:8080/gateway/v1/provider-health
        ```

        Add `.env` and `.sentinelguard/` to your project `.gitignore` before
        storing real keys or local gateway state.
        """
    )


def _normalize_choice(value: str, choices: tuple[str, ...], field_name: str) -> str:
    normalized = (value or "").strip().lower().replace("_", "-")
    if normalized not in choices:
        joined = ", ".join(choices)
        raise ValueError(f"Unsupported {field_name} '{value}'. Choose one of: {joined}")
    return normalized
