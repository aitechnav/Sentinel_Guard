"""Tests for privacy-safe audit logging."""

import json
import logging

from sentinelguard.audit import (
    AUDIT_LOGGER_NAME,
    build_audit_context,
    hash_identifier,
    log_scan_detections,
)
from sentinelguard.core.scanner import AggregatedResult, RiskLevel, ScanResult


def test_hash_identifier_is_stable_and_not_raw():
    first = hash_identifier("alice@example.com", salt="pepper")
    second = hash_identifier("alice@example.com", salt="pepper")
    different_salt = hash_identifier("alice@example.com", salt="different")

    assert first == second
    assert first != different_salt
    assert first.startswith("sha256:")
    assert "alice@example.com" not in first


def test_build_audit_context_hashes_user_and_tenant(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_AUDIT_SALT", "pepper")

    context = build_audit_context(
        {
            "X-Request-ID": "req-123",
            "X-User-ID": "alice@example.com",
            "X-Tenant-ID": "tenant-a",
        },
        {},
    )

    assert context.request_id == "req-123"
    assert context.user_hash
    assert context.tenant_hash
    assert "alice@example.com" not in context.user_hash
    assert "tenant-a" not in context.tenant_hash


def test_build_audit_context_uses_payload_user_when_header_missing(monkeypatch):
    monkeypatch.setenv("SENTINELGUARD_AUDIT_SALT", "pepper")

    context = build_audit_context(
        {},
        {"user": "chat-user-1", "metadata": {"tenant_id": "tenant-a"}},
    )

    assert context.request_id.startswith("req_")
    assert context.user_hash == hash_identifier("chat-user-1", salt="pepper")
    assert context.tenant_hash == hash_identifier("tenant-a", salt="pepper")


def test_log_scan_detections_excludes_sensitive_values(caplog):
    context = build_audit_context(
        {"X-Request-ID": "req-123", "X-User-ID": "alice@example.com"},
        {},
    )
    result = AggregatedResult(
        is_valid=False,
        results=[
            ScanResult(
                is_valid=False,
                score=1.0,
                risk_level=RiskLevel.CRITICAL,
                scanner_name="secrets",
                details={"matched_secret": "sk-proj-sensitive"},
            )
        ],
        failed_scanners=["secrets"],
        scanner_actions={"secrets": "block"},
        total_latency_ms=4.0,
    )

    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)

    log_scan_detections(
        context,
        provider="openai",
        streaming=False,
        direction="prompt",
        result=result,
    )

    log_text = caplog.text
    assert "alice@example.com" not in log_text
    assert "sk-proj-sensitive" not in log_text

    event = json.loads(caplog.records[0].message)
    assert event["event"] == "sentinelguard_detection"
    assert event["request_id"] == "req-123"
    assert event["category"] == "secret"
    assert event["scanner"] == "secrets"
    assert event["risk_level"] == "critical"
    assert event["action"] == "block"
    assert event["provider"] == "openai"
    assert event["streaming"] is False
    assert event["user_hash"].startswith("sha256:")
