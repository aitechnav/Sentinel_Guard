"""Optional gateway observability integrations."""

from __future__ import annotations

from contextlib import contextmanager
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


@contextmanager
def gateway_trace_span(
    config: GatewayConfig,
    name: str,
    attributes: Mapping[str, Any],
):
    """Create an optional OpenTelemetry span for gateway internals."""
    if not config.otel_enabled:
        yield None
        return
    try:
        from opentelemetry import trace
    except Exception:
        yield None
        return

    tracer = trace.get_tracer("sentinelguard.gateway")
    try:
        manager = tracer.start_as_current_span(name)
        span = manager.__enter__()
    except Exception:
        yield None
        return

    try:
        _set_span_attributes(span, attributes)
        yield span
    except Exception as exc:
        suppress = manager.__exit__(type(exc), exc, exc.__traceback__)
        if not suppress:
            raise
    else:
        manager.__exit__(None, None, None)


def _set_span_attributes(span: Any, attributes: Mapping[str, Any]) -> None:
    for key, value in attributes.items():
        if value is None:
            continue
        try:
            span.set_attribute(str(key), _span_attribute_value(value))
        except Exception:
            continue


def _span_attribute_value(value: Any) -> Any:
    if isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item) for item in value)
    return str(value)
