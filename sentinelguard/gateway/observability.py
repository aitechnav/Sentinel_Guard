"""Optional gateway observability integrations."""

from __future__ import annotations

from typing import Any, Mapping

from sentinelguard.gateway.config import GatewayConfig


def emit_gateway_event(
    config: GatewayConfig,
    name: str,
    attributes: Mapping[str, Any],
) -> None:
    """Emit an optional gateway event to configured observability backends."""
    if config.otel_enabled:
        _emit_otel_event(name, attributes)
    if config.langfuse_enabled:
        _emit_langfuse_event(name, attributes)


def _emit_otel_event(name: str, attributes: Mapping[str, Any]) -> None:
    try:
        from opentelemetry import trace
    except Exception:
        return
    span = trace.get_current_span()
    if span is None:
        return
    try:
        span.add_event(name, dict(attributes))
    except Exception:
        return


def _emit_langfuse_event(name: str, attributes: Mapping[str, Any]) -> None:
    try:
        from langfuse import Langfuse
    except Exception:
        return
    try:
        Langfuse().event(name=name, metadata=dict(attributes))
    except Exception:
        return
