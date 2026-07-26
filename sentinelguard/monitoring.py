"""Optional Prometheus metrics for SentinelGuard.

Metrics intentionally use low-cardinality, non-sensitive labels. Never expose
prompt text, response text, matched secrets, PII values, or user identifiers in
Prometheus labels.
"""

from __future__ import annotations

from typing import Optional

from sentinelguard.core.scanner import AggregatedResult

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

    PROMETHEUS_AVAILABLE = True
except ImportError:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    Counter = None  # type: ignore[assignment]
    Histogram = None  # type: ignore[assignment]
    generate_latest = None  # type: ignore[assignment]
    PROMETHEUS_AVAILABLE = False


ATTACK_SCANNERS = {
    "prompt_injection",
    "jailbreak",
    "invisible_text",
    "supply_chain",
    "data_poisoning",
    "unbounded_consumption",
    "code",
    "ban_code",
}
PII_SCANNERS = {"pii", "anonymize", "deanonymize"}
SECRET_SCANNERS = {"secrets", "data_leakage", "sensitive", "system_prompt_leakage"}


if PROMETHEUS_AVAILABLE:
    GATEWAY_REQUESTS = Counter(
        "sentinelguard_gateway_requests_total",
        "Total SentinelGuard gateway chat requests.",
        ["provider", "streaming", "outcome"],
    )
    SCANS = Counter(
        "sentinelguard_scans_total",
        "Total SentinelGuard scans by direction and result.",
        ["direction", "result"],
    )
    DETECTIONS = Counter(
        "sentinelguard_detections_total",
        "Total SentinelGuard scanner detections.",
        ["direction", "scanner", "category", "risk_level", "action"],
    )
    PROVIDER_ATTEMPTS = Counter(
        "sentinelguard_provider_attempts_total",
        "Total SentinelGuard upstream provider attempts.",
        ["provider", "result"],
    )
    PROVIDER_FAILOVERS = Counter(
        "sentinelguard_provider_failovers_total",
        "Total SentinelGuard provider failover events.",
        ["from_provider", "to_provider"],
    )
    SCAN_LATENCY = Histogram(
        "sentinelguard_scan_latency_seconds",
        "SentinelGuard scan latency in seconds.",
        ["direction"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
else:
    GATEWAY_REQUESTS = None
    SCANS = None
    DETECTIONS = None
    PROVIDER_ATTEMPTS = None
    PROVIDER_FAILOVERS = None
    SCAN_LATENCY = None


def prometheus_available() -> bool:
    """Return True when prometheus-client is installed."""
    return PROMETHEUS_AVAILABLE


def metrics_content_type() -> str:
    """Return the Prometheus text exposition content type."""
    return CONTENT_TYPE_LATEST


def render_metrics() -> bytes:
    """Render Prometheus metrics in text exposition format."""
    if not PROMETHEUS_AVAILABLE or generate_latest is None:
        return b""
    return generate_latest()


def scanner_category(scanner_name: str) -> str:
    """Classify scanner names into alert-friendly categories."""
    if scanner_name in PII_SCANNERS:
        return "pii"
    if scanner_name in SECRET_SCANNERS:
        return "secret"
    if scanner_name in ATTACK_SCANNERS:
        return "attack"
    return "other"


def record_gateway_request(provider: str, streaming: bool, outcome: str) -> None:
    """Record one gateway request outcome."""
    if GATEWAY_REQUESTS is None:
        return
    GATEWAY_REQUESTS.labels(
        provider=provider,
        streaming=str(streaming).lower(),
        outcome=outcome,
    ).inc()


def record_scan(direction: str, result: AggregatedResult) -> None:
    """Record aggregate scan metrics and per-scanner detections."""
    if SCANS is None or DETECTIONS is None or SCAN_LATENCY is None:
        return

    scan_result = "passed" if result.is_valid else "failed"
    SCANS.labels(direction=direction, result=scan_result).inc()
    SCAN_LATENCY.labels(direction=direction).observe(result.total_latency_ms / 1000.0)

    for scan in result.results:
        if scan.is_valid:
            continue
        action = _safe_action(result.scanner_actions.get(scan.scanner_name))
        DETECTIONS.labels(
            direction=direction,
            scanner=scan.scanner_name,
            category=scanner_category(scan.scanner_name),
            risk_level=scan.risk_level.value,
            action=action,
        ).inc()


def record_provider_attempts(attempts: object) -> None:
    """Record provider attempts and failovers from a routed gateway request."""
    if PROVIDER_ATTEMPTS is None or PROVIDER_FAILOVERS is None:
        return

    attempts_list = list(attempts or [])
    for attempt in attempts_list:
        PROVIDER_ATTEMPTS.labels(
            provider=getattr(attempt, "provider", "unknown"),
            result=_attempt_result(attempt),
        ).inc()

    for previous, current in zip(attempts_list, attempts_list[1:]):
        PROVIDER_FAILOVERS.labels(
            from_provider=getattr(previous, "provider", "unknown"),
            to_provider=getattr(current, "provider", "unknown"),
        ).inc()


def _safe_action(action: Optional[str]) -> str:
    if not action:
        return "block"
    normalized = action.lower()
    if normalized in {"block", "warn", "allow", "sanitize", "redact"}:
        return normalized
    return "other"


def _attempt_result(attempt: object) -> str:
    if getattr(attempt, "error", None):
        return "exception"
    status_code = getattr(attempt, "status_code", None)
    if isinstance(status_code, int) and status_code < 400:
        return "success"
    return "error"
