"""SentinelGuard CLI tool.

Provides command-line interface for scanning text, managing
configuration, and running the API server.

Usage:
    sentinelguard scan prompt "Your text here"
    sentinelguard scan output "LLM output here"
    sentinelguard serve --port 8000
    sentinelguard gateway --provider openai --port 8080
    sentinelguard gateway --provider anthropic --port 8080
    sentinelguard gateway --provider gemini --port 8080
    sentinelguard config show
    sentinelguard scanners list
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sentinelguard",
        description="SentinelGuard - LLM Security & Guardrails Framework",
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version"
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── scan command ──
    scan_parser = subparsers.add_parser("scan", help="Scan text for security issues")
    scan_parser.add_argument(
        "type", choices=["prompt", "output"], help="Type of scan"
    )
    scan_parser.add_argument("text", help="Text to scan")
    scan_parser.add_argument(
        "--config", type=str, help="Path to config YAML file"
    )
    scan_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    scan_parser.add_argument(
        "--threshold", type=float, help="Override threshold"
    )

    # ── serve command ──
    serve_parser = subparsers.add_parser("serve", help="Start API server")
    serve_parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind to"
    )
    serve_parser.add_argument(
        "--port", type=int, default=8000, help="Port to listen on"
    )
    serve_parser.add_argument(
        "--config", type=str, help="Path to config YAML file"
    )
    serve_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload"
    )

    # ── gateway command ──
    gateway_parser = subparsers.add_parser(
        "gateway", help="Start OpenAI-compatible LLM gateway"
    )
    gateway_parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind to"
    )
    gateway_parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on"
    )
    gateway_parser.add_argument(
        "--config", type=str, help="Path to SentinelGuard scanner config YAML"
    )
    gateway_parser.add_argument(
        "--gateway-config", type=str, help="Path to gateway config YAML"
    )
    gateway_parser.add_argument(
        "--provider",
        default=None,
        help="Gateway provider: openai, anthropic, gemini, or OpenAI-compatible",
    )
    gateway_parser.add_argument(
        "--upstream-url", default=None, help="OpenAI-compatible upstream base URL"
    )
    gateway_parser.add_argument(
        "--api-key-env", default=None, help="Environment variable for upstream API key"
    )
    gateway_parser.add_argument(
        "--enabled", choices=["true", "false"], default=None, help="Enable scanning"
    )
    gateway_parser.add_argument(
        "--sanitize", choices=["true", "false"], default=None, help="Forward sanitized text"
    )
    gateway_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload"
    )

    # ── config command ──
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_sub = config_parser.add_subparsers(dest="config_action")
    config_sub.add_parser("show", help="Show current configuration")
    config_init = config_sub.add_parser("init", help="Create default config file")
    config_init.add_argument(
        "--preset",
        choices=["minimal", "standard", "strict"],
        default="standard",
        help="Configuration preset",
    )
    config_init.add_argument(
        "--output", type=str, default="sentinelguard.yaml", help="Output file path"
    )

    # ── scanners command ──
    scanners_parser = subparsers.add_parser("scanners", help="List scanners")
    scanners_parser.add_argument(
        "action", choices=["list"], help="Action to perform"
    )

    args = parser.parse_args(argv)

    if args.version:
        from sentinelguard import __version__
        print(f"sentinelguard {__version__}")
        return 0

    if args.command == "scan":
        return _handle_scan(args)
    elif args.command == "serve":
        return _handle_serve(args)
    elif args.command == "gateway":
        return _handle_gateway(args)
    elif args.command == "config":
        return _handle_config(args)
    elif args.command == "scanners":
        return _handle_scanners(args)
    else:
        parser.print_help()
        return 0


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle the scan command."""
    from sentinelguard import SentinelGuard, GuardConfig

    config = None
    if args.config:
        config = GuardConfig.from_yaml(args.config)

    guard = SentinelGuard(config=config)
    if args.threshold is not None:
        _apply_threshold(guard, args.threshold)

    if args.type == "prompt":
        result = guard.scan_prompt(args.text)
    else:
        result = guard.scan_output(args.text)

    if args.format == "json":
        output = {
            "is_valid": result.is_valid,
            "failed_scanners": result.failed_scanners,
            "total_latency_ms": round(result.total_latency_ms, 2),
            "highest_risk": result.highest_risk.value,
            "results": [
                {
                    "scanner": r.scanner_name,
                    "is_valid": r.is_valid,
                    "score": round(r.score, 4),
                    "risk_level": r.risk_level.value,
                    "details": r.details,
                    "latency_ms": round(r.latency_ms, 2),
                }
                for r in result.results
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        status = "PASS" if result.is_valid else "FAIL"
        print(f"\n{'='*60}")
        print(f"  SentinelGuard Scan Result: {status}")
        print(f"{'='*60}")
        print(f"  Type: {args.type}")
        print(f"  Valid: {result.is_valid}")
        print(f"  Highest Risk: {result.highest_risk.value}")
        print(f"  Latency: {result.total_latency_ms:.1f}ms")

        if result.failed_scanners:
            print("\n  Failed Scanners:")
            for name in result.failed_scanners:
                print(f"    - {name}")

        print("\n  Scanner Results:")
        for r in result.results:
            icon = "+" if r.is_valid else "x"
            print(
                f"    [{icon}] {r.scanner_name}: "
                f"score={r.score:.3f} "
                f"risk={r.risk_level.value} "
                f"({r.latency_ms:.1f}ms)"
            )
        print(f"{'='*60}\n")

    return 0 if result.is_valid else 1


def _apply_threshold(guard, threshold: float) -> None:
    """Apply a threshold override to all active scanners for this CLI run."""
    for scanner in guard._prompt_pipeline.scanners:
        scanner.threshold = threshold
    for scanner in guard._output_pipeline.scanners:
        scanner.threshold = threshold


def _handle_serve(args: argparse.Namespace) -> int:
    """Handle the serve command."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required. Install with: pip install sentinelguard[api]")
        return 1

    from sentinelguard.core.config import GuardConfig

    config = None
    if args.config:
        config = GuardConfig.from_yaml(args.config)

    from sentinelguard.api.server import create_app
    app = create_app(config)

    print(f"Starting SentinelGuard API server on {args.host}:{args.port}")
    print(f"Docs available at http://{args.host}:{args.port}/docs")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def _handle_gateway(args: argparse.Namespace) -> int:
    """Handle the gateway command."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required. Install with: pip install sentinelguard[gateway]")
        return 1

    from sentinelguard.core.config import GuardConfig
    from sentinelguard.gateway.config import GatewayConfig
    from sentinelguard.gateway.providers import (
        effective_api_key_env,
        effective_provider,
        effective_upstream_url,
    )
    from sentinelguard.gateway.server import create_gateway_app

    guard_config = GuardConfig.from_yaml(args.config) if args.config else None
    gateway_config = (
        GatewayConfig.from_yaml(args.gateway_config)
        if args.gateway_config
        else GatewayConfig()
    )

    if args.provider is not None:
        gateway_config.provider = args.provider
    if args.upstream_url is not None:
        gateway_config.upstream_url = args.upstream_url
    if args.api_key_env is not None:
        gateway_config.api_key_env = args.api_key_env
    if args.enabled is not None:
        gateway_config.enabled = _parse_bool(args.enabled)
    if args.sanitize is not None:
        gateway_config.sanitize = _parse_bool(args.sanitize)

    app = create_gateway_app(
        guard_config=guard_config,
        gateway_config=gateway_config,
    )

    mode = "enabled" if gateway_config.enabled else "pass-through"
    print(f"Starting SentinelGuard LLM gateway on {args.host}:{args.port}")
    print(f"Gateway mode: {mode}")
    print(f"Provider: {effective_provider(gateway_config)}")
    print(f"Upstream: {effective_upstream_url(gateway_config)}")
    print(f"API key env: {effective_api_key_env(gateway_config)}")
    print(f"Streaming mode: {gateway_config.streaming_mode}")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def _parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def _handle_config(args: argparse.Namespace) -> int:
    """Handle the config command."""
    from sentinelguard.core.config import GuardConfig

    if args.config_action == "show":
        config = GuardConfig.preset_standard()
        print(json.dumps(config.to_dict(), indent=2))
    elif args.config_action == "init":
        if args.preset == "minimal":
            config = GuardConfig.preset_minimal()
        elif args.preset == "strict":
            config = GuardConfig.preset_strict()
        else:
            config = GuardConfig.preset_standard()

        config.save_yaml(args.output)
        print(f"Configuration saved to {args.output}")
    else:
        print("Use: sentinelguard config show|init")

    return 0


def _handle_scanners(args: argparse.Namespace) -> int:
    """Handle the scanners command."""
    from sentinelguard.core.scanner import ScannerRegistry

    # Trigger scanner registration
    import sentinelguard.scanners.prompt  # noqa: F401
    import sentinelguard.scanners.output  # noqa: F401

    if args.action == "list":
        print("\nPrompt Scanners:")
        for name in sorted(ScannerRegistry.list_prompt_scanners()):
            print(f"  - {name}")

        print("\nOutput Scanners:")
        for name in sorted(ScannerRegistry.list_output_scanners()):
            print(f"  - {name}")

        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
