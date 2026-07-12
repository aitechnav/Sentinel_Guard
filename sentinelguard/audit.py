"""Privacy-safe audit logging for SentinelGuard gateway detections."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from sentinelguard.core.scanner import AggregatedResult
from sentinelguard.monitoring import scanner_category

AUDIT_LOGGER_NAME = "sentinelguard.audit"
DEFAULT_AUDIT_SALT_ENV = "SENTINELGUARD_AUDIT_SALT"

logger = logging.getLogger(AUDIT_LOGGER_NAME)


@dataclass(frozen=True)
class AuditContext:
    """Safe request identity fields for audit events."""

    request_id: str
    user_hash: Optional[str] = None
    tenant_hash: Optional[str] = None


def build_audit_context(
    headers: Mapping[str, str],
    payload: Mapping[str, Any],
    *,
    salt_env: str = DEFAULT_AUDIT_SALT_ENV,
) -> AuditContext:
    """Build a privacy-safe audit context from headers and OpenAI payload.

    User and tenant identifiers are hashed before logging. Request IDs are
    sanitized and truncated because they are operational correlation IDs, not
    user data.
    """
    incoming = {str(key).lower(): str(value) for key, value in headers.items()}
    salt = os.getenv(salt_env, "")

    request_id = _first_value(
        incoming,
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "traceparent",
    )
    user_id = _first_value(
        incoming,
        "x-user-id",
        "x-user",
        "x-end-user",
        "x-authenticated-user",
    ) or _payload_user(payload)
    tenant_id = _first_value(
        incoming,
        "x-tenant-id",
        "x-tenant",
        "x-organization-id",
        "x-org-id",
        "x-workspace-id",
    ) or _payload_metadata_value(payload, "tenant_id", "tenant", "organization_id")

    return AuditContext(
        request_id=_safe_request_id(request_id),
        user_hash=hash_identifier(user_id, salt=salt),
        tenant_hash=hash_identifier(tenant_id, salt=salt),
    )


def hash_identifier(value: Optional[str], *, salt: str = "") -> Optional[str]:
    """Hash an identifier for logs without exposing the raw value."""
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    digest = hashlib.sha256(f"{salt}:{normalized}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def log_scan_detections(
    context: AuditContext,
    *,
    provider: str,
    streaming: bool,
    direction: str,
    result: AggregatedResult,
) -> None:
    """Log one JSON audit event per failed scanner result."""
    for scan in result.results:
        if scan.is_valid:
            continue
        action = _safe_action(result.scanner_actions.get(scan.scanner_name))
        event = {
            "event": "sentinelguard_detection",
            "request_id": context.request_id,
            "user_hash": context.user_hash,
            "tenant_hash": context.tenant_hash,
            "provider": provider,
            "streaming": streaming,
            "direction": direction,
            "category": scanner_category(scan.scanner_name),
            "scanner": scan.scanner_name,
            "risk_level": scan.risk_level.value,
            "action": action,
        }
        logger.info(json.dumps(event, sort_keys=True, separators=(",", ":")))


def _first_value(mapping: Mapping[str, str], *names: str) -> Optional[str]:
    for name in names:
        value = mapping.get(name)
        if value:
            return value
    return None


def _payload_user(payload: Mapping[str, Any]) -> Optional[str]:
    user = payload.get("user")
    if user is not None:
        return str(user)
    return _payload_metadata_value(payload, "user_id", "user", "end_user")


def _payload_metadata_value(payload: Mapping[str, Any], *names: str) -> Optional[str]:
    metadata = payload.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    for name in names:
        value = metadata.get(name)
        if value is not None:
            return str(value)
    return None


def _safe_request_id(value: Optional[str]) -> str:
    if not value:
        return f"req_{uuid.uuid4().hex}"
    sanitized = re.sub(r"[^A-Za-z0-9_.:-]", "_", str(value).strip())
    return sanitized[:128] or f"req_{uuid.uuid4().hex}"


def _safe_action(action: Optional[str]) -> str:
    if not action:
        return "block"
    normalized = action.lower()
    if normalized in {"block", "warn", "allow", "sanitize", "redact"}:
        return normalized
    return "other"
