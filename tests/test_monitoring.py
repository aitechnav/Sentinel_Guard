"""Tests for optional Prometheus monitoring helpers."""

from sentinelguard.core.scanner import AggregatedResult, RiskLevel, ScanResult
from sentinelguard.monitoring import (
    prometheus_available,
    record_gateway_request,
    record_scan,
    render_metrics,
    scanner_category,
)


def test_scanner_category_groups_alert_types():
    assert scanner_category("pii") == "pii"
    assert scanner_category("anonymize") == "pii"
    assert scanner_category("secrets") == "secret"
    assert scanner_category("data_leakage") == "secret"
    assert scanner_category("prompt_injection") == "attack"
    assert scanner_category("jailbreak") == "attack"
    assert scanner_category("bias") == "other"


def test_monitoring_helpers_are_safe_without_required_dependency():
    result = AggregatedResult(
        is_valid=False,
        results=[
            ScanResult(
                is_valid=False,
                score=1.0,
                risk_level=RiskLevel.CRITICAL,
                scanner_name="secrets",
            )
        ],
        failed_scanners=["secrets"],
        scanner_actions={"secrets": "block"},
        total_latency_ms=12.0,
    )

    record_scan("prompt", result)
    record_gateway_request("openai", False, "blocked_prompt")

    if not prometheus_available():
        assert render_metrics() == b""
