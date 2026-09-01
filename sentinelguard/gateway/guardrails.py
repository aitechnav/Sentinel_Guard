"""Named guardrail orchestration for SentinelGuard gateway mode."""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from sentinelguard.core.guard import SentinelGuard
from sentinelguard.core.scanner import AggregatedResult
from sentinelguard.gateway.config import GatewayConfig, GatewayGuardrailConfig
from sentinelguard.gateway.observability import emit_gateway_event, gateway_trace_span
from sentinelguard.gateway.operations import GatewayClient
from sentinelguard.gateway.policy import (
    PolicyAction,
    PolicyDecision,
    evaluate_output_policy,
    evaluate_prompt_policy,
)
from sentinelguard.monitoring import (
    record_guardrail_decision,
    record_scan,
    scanner_category,
)

DEFAULT_GUARDRAIL_NAME = "sentinelguard-default"
MANUAL_STAGE = "manual"


@dataclass(frozen=True)
class GuardrailExecution:
    """One named guardrail decision produced from a scan result."""

    name: str
    stage: str
    direction: str
    mode: str
    decision: PolicyDecision
    latency_ms: float = 0.0

    @property
    def enforced(self) -> bool:
        return self.mode == "enforce"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stage": self.stage,
            "direction": self.direction,
            "mode": self.mode,
            "enforced": self.enforced,
            "allowed": self.decision.allowed,
            "action": self.decision.action.value,
            "reason_codes": list(self.decision.reason_codes),
            "failed_scanners": list(self.decision.failed_scanners),
            "warning_scanners": list(self.decision.warning_scanners),
            "highest_risk": self.decision.highest_risk,
            "route_constraint": self.decision.route_constraint,
            "latency_ms": round(self.latency_ms, 3),
        }


@dataclass(frozen=True)
class GuardrailApplyResult:
    """Result returned after applying named gateway guardrails."""

    direction: str
    stage: str
    scan: AggregatedResult
    decision: PolicyDecision
    executions: tuple[GuardrailExecution, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed

    @property
    def sanitized_text(self) -> Optional[str]:
        return self.decision.sanitized_text

    @property
    def has_enforced_guardrail(self) -> bool:
        return any(execution.enforced for execution in self.executions)

    def to_dict(self, *, include_text: bool = False) -> dict[str, Any]:
        payload = {
            "object": "sentinelguard.guardrail.apply",
            "allowed": self.allowed,
            "action": self.decision.action.value,
            "direction": self.direction,
            "stage": self.stage,
            "highest_risk": self.decision.highest_risk,
            "route_constraint": self.decision.route_constraint,
            "reason_codes": list(self.decision.reason_codes),
            "failed_scanners": list(self.decision.failed_scanners),
            "warning_scanners": list(self.decision.warning_scanners),
            "scan": _scan_summary(self.scan),
            "guardrails": [execution.to_dict() for execution in self.executions],
        }
        if include_text and self.sanitized_text is not None:
            payload["sanitized_text"] = self.sanitized_text
        return payload


class SensitiveSessionRouteStore:
    """Small TTL store for sessions that should remain on private providers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._routes: dict[str, float] = {}

    def remember(self, key: str, ttl_seconds: int) -> None:
        if not key:
            return
        ttl = max(1, int(ttl_seconds or 1))
        with self._lock:
            self._routes[key] = time.time() + ttl

    def is_active(self, key: Optional[str]) -> bool:
        if not key:
            return False
        now = time.time()
        with self._lock:
            expires_at = self._routes.get(key)
            if expires_at is None:
                return False
            if expires_at <= now:
                self._routes.pop(key, None)
                return False
            return True

    def snapshot(self) -> dict[str, int]:
        now = time.time()
        with self._lock:
            expired = [key for key, expires_at in self._routes.items() if expires_at <= now]
            for key in expired:
                self._routes.pop(key, None)
            return {key: int(expires_at) for key, expires_at in self._routes.items()}

    def reset(self) -> None:
        with self._lock:
            self._routes.clear()


_SENSITIVE_ROUTE_STORE = SensitiveSessionRouteStore()


def sensitive_route_store() -> SensitiveSessionRouteStore:
    """Return the process-local sensitive-session routing store."""
    return _SENSITIVE_ROUTE_STORE


async def apply_gateway_guardrails(
    guard: SentinelGuard,
    text: str,
    config: GatewayConfig,
    *,
    direction: str,
    stage: str,
    prompt: Optional[str] = None,
    requested_guardrails: Sequence[str] = (),
    metric_direction: Optional[str] = None,
    streaming: bool = False,
) -> GuardrailApplyResult:
    """Scan text once and apply all active named guardrails for the stage."""
    normalized_direction = _normalize_direction(direction)
    normalized_stage = _normalize_stage(stage)
    active = active_guardrails(
        config,
        stage=normalized_stage,
        direction=normalized_direction,
        requested_guardrails=requested_guardrails,
    )
    if not active:
        decision = PolicyDecision(
            action=PolicyAction.ALLOW,
            direction=normalized_direction,
            reason_codes=["guardrail_stage_not_configured"],
        )
        return GuardrailApplyResult(
            direction=normalized_direction,
            stage=normalized_stage,
            scan=AggregatedResult(is_valid=True),
            decision=decision,
        )

    span_attrs = {
        "sentinelguard.guardrail.stage": normalized_stage,
        "sentinelguard.guardrail.direction": normalized_direction,
        "sentinelguard.guardrail.names": [guardrail.name for guardrail in active],
        "sentinelguard.guardrail.streaming": streaming,
    }
    with gateway_trace_span(config, "sentinelguard.guardrail.apply", span_attrs) as span:
        started_at = time.perf_counter()
        scan = await _scan_text(guard, text, normalized_direction, prompt=prompt)
        record_scan(metric_direction or normalized_direction, scan)
        base_decision = _evaluate_text_policy(text, scan, config, normalized_direction)
        elapsed_ms = (time.perf_counter() - started_at) * 1000
        effective_decision = _effective_decision(base_decision, active, normalized_direction)
        executions = tuple(
            GuardrailExecution(
                name=guardrail.name,
                stage=normalized_stage,
                direction=normalized_direction,
                mode=_normalize_mode(guardrail.mode),
                decision=base_decision,
                latency_ms=elapsed_ms,
            )
            for guardrail in active
        )
        for execution in executions:
            record_guardrail_decision(
                execution.name,
                normalized_stage,
                normalized_direction,
                execution.mode,
                execution.decision.action.value,
                execution.latency_ms,
            )
            emit_gateway_event(
                config,
                "sentinelguard.guardrail.decision",
                {
                    "guardrail": execution.name,
                    "stage": normalized_stage,
                    "direction": normalized_direction,
                    "mode": execution.mode,
                    "allowed": execution.decision.allowed,
                    "action": execution.decision.action.value,
                    "highest_risk": execution.decision.highest_risk,
                    "streaming": streaming,
                },
            )
        if span is not None:
            try:
                span.set_attribute("sentinelguard.guardrail.allowed", effective_decision.allowed)
                span.set_attribute("sentinelguard.guardrail.action", effective_decision.action.value)
                span.set_attribute("sentinelguard.guardrail.highest_risk", effective_decision.highest_risk)
            except Exception:
                pass

    return GuardrailApplyResult(
        direction=normalized_direction,
        stage=normalized_stage,
        scan=scan,
        decision=effective_decision,
        executions=executions,
    )


def active_guardrails(
    config: GatewayConfig,
    *,
    stage: str,
    direction: str,
    requested_guardrails: Sequence[str] = (),
) -> list[GatewayGuardrailConfig]:
    """Return guardrails enabled for one stage and direction."""
    requested = {name.strip() for name in requested_guardrails if name and name.strip()}
    configured = list(config.guardrails) or [_default_guardrail()]
    default_names = {name.strip() for name in config.default_guardrail_names if name and name.strip()}
    if requested:
        selected_names = requested
    elif default_names:
        selected_names = default_names
    else:
        selected_names = set()

    active: list[GatewayGuardrailConfig] = []
    for guardrail in configured:
        if not guardrail.enabled:
            continue
        if selected_names and guardrail.name not in selected_names:
            continue
        if not _direction_matches(guardrail.directions, direction):
            continue
        if not _stage_matches(guardrail.stages, stage):
            continue
        active.append(guardrail)
    return active


def guardrail_summary(config: GatewayConfig) -> list[dict[str, Any]]:
    """Return non-sensitive configured guardrail metadata."""
    return [guardrail.to_dict() for guardrail in (config.guardrails or [_default_guardrail()])]


def requested_guardrail_names(
    headers: Optional[Mapping[str, str]] = None,
    payload: Optional[Mapping[str, Any]] = None,
) -> tuple[str, ...]:
    """Extract request-selected guardrail names from headers or JSON metadata."""
    names: list[str] = []
    header_value = _case_insensitive_get(headers or {}, "x-sentinelguard-guardrails")
    names.extend(_split_names(header_value))

    body = payload or {}
    names.extend(_coerce_names(body.get("guardrails")))
    metadata = body.get("metadata")
    if isinstance(metadata, Mapping):
        names.extend(_coerce_names(metadata.get("guardrails")))
    return tuple(dict.fromkeys(name for name in names if name))


def unknown_requested_guardrails(
    config: GatewayConfig,
    requested_guardrails: Sequence[str],
) -> list[str]:
    """Return requested guardrail names not configured on this gateway."""
    if not requested_guardrails:
        return []
    configured = {guardrail.name for guardrail in (config.guardrails or [_default_guardrail()])}
    return [name for name in requested_guardrails if name not in configured]


def has_sensitive_detection(scan: AggregatedResult) -> bool:
    """Return True when a scan found PII or secret-like content."""
    for result in scan.results:
        if result.is_valid:
            continue
        if scanner_category(result.scanner_name) in {"pii", "secret"}:
            return True
    return False


def resolve_sensitive_session_key(
    headers: Mapping[str, str],
    client: GatewayClient,
    payload: Mapping[str, Any],
    config: GatewayConfig,
) -> Optional[str]:
    """Build a privacy-safe key for sticky sensitive-data routing."""
    if not config.sensitive_session_routing_enabled:
        return None

    for header in config.sensitive_session_headers:
        value = _case_insensitive_get(headers, header)
        if value:
            return _stable_hash(f"{client.key_id}:session:{value}")

    user = str(payload.get("user") or "").strip()
    if user:
        return _stable_hash(f"{client.key_id}:user:{user}")

    if config.sensitive_session_fallback_to_client:
        return _stable_hash(f"{client.key_id}:client")
    return None


def sensitive_session_active(config: GatewayConfig, session_key: Optional[str]) -> bool:
    """Return True when a session is currently pinned to private routing."""
    if not config.sensitive_session_routing_enabled:
        return False
    return sensitive_route_store().is_active(session_key)


def remember_sensitive_session_if_needed(
    config: GatewayConfig,
    session_key: Optional[str],
    scan: AggregatedResult,
    decision: PolicyDecision,
) -> bool:
    """Pin a sensitive session to private routing when policy found sensitive data."""
    if not config.sensitive_session_routing_enabled or not session_key:
        return False
    if decision.route_constraint != "private" and not has_sensitive_detection(scan):
        return False
    sensitive_route_store().remember(session_key, config.sensitive_session_ttl_seconds)
    return True


def _default_guardrail() -> GatewayGuardrailConfig:
    return GatewayGuardrailConfig(
        name=DEFAULT_GUARDRAIL_NAME,
        mode="enforce",
        stages=["pre_call", "post_call", "passthrough", MANUAL_STAGE],
        directions=["prompt", "output", "passthrough"],
        description="Default SentinelGuard scanner policy",
    )


def _effective_decision(
    base_decision: PolicyDecision,
    guardrails: Sequence[GatewayGuardrailConfig],
    direction: str,
) -> PolicyDecision:
    if any(_normalize_mode(guardrail.mode) == "enforce" for guardrail in guardrails):
        return base_decision
    return PolicyDecision(
        action=PolicyAction.ALLOW,
        direction=direction,
        reason_codes=list(base_decision.reason_codes),
        failed_scanners=list(base_decision.failed_scanners),
        warning_scanners=list(base_decision.warning_scanners),
        highest_risk=base_decision.highest_risk,
        route_constraint=base_decision.route_constraint,
    )


async def _scan_text(
    guard: SentinelGuard,
    text: str,
    direction: str,
    *,
    prompt: Optional[str] = None,
) -> AggregatedResult:
    if direction == "output":
        return await guard.scan_output_async(text, prompt=prompt)
    return await guard.scan_prompt_async(text)


def _evaluate_text_policy(
    text: str,
    scan: AggregatedResult,
    config: GatewayConfig,
    direction: str,
) -> PolicyDecision:
    if direction == "output":
        return evaluate_output_policy(text, scan, config)
    return evaluate_prompt_policy(text, scan, config)


def _scan_summary(scan: AggregatedResult) -> dict[str, Any]:
    return {
        "valid": scan.is_valid,
        "failed_scanners": list(scan.failed_scanners),
        "warning_scanners": list(scan.warning_scanners),
        "highest_risk": scan.highest_risk.value,
        "total_latency_ms": round(scan.total_latency_ms, 3),
        "scanners": [
            {
                "name": result.scanner_name,
                "valid": result.is_valid,
                "score": round(result.score, 4),
                "risk_level": result.risk_level.value,
                "latency_ms": round(result.latency_ms, 3),
                "category": scanner_category(result.scanner_name),
            }
            for result in scan.results
        ],
    }


def _normalize_direction(direction: str) -> str:
    normalized = str(direction or "prompt").strip().lower()
    if normalized in {"response", "completion", "post_call"}:
        return "output"
    if normalized in {"mcp", "a2a", "passthrough", "request", "pre_call"}:
        return "prompt"
    if normalized not in {"prompt", "output"}:
        return "prompt"
    return normalized


def _normalize_stage(stage: str) -> str:
    normalized = str(stage or MANUAL_STAGE).strip().lower().replace("-", "_")
    if normalized in {"pre", "input"}:
        return "pre_call"
    if normalized in {"post", "response", "output"}:
        return "post_call"
    if normalized not in {"pre_call", "post_call", "passthrough", MANUAL_STAGE}:
        return MANUAL_STAGE
    return normalized


def _normalize_mode(mode: str) -> str:
    normalized = str(mode or "enforce").strip().lower().replace("-", "_")
    if normalized in {"log", "log_only", "logging"}:
        return "logging_only"
    if normalized != "logging_only":
        return "enforce"
    return normalized


def _stage_matches(stages: Sequence[str], stage: str) -> bool:
    if stage == MANUAL_STAGE:
        return True
    raw = {str(item).strip().lower().replace("-", "_") for item in stages if str(item).strip()}
    if not raw or "all" in raw:
        return True
    normalized = {_normalize_stage(item) for item in raw}
    return stage in normalized


def _direction_matches(directions: Sequence[str], direction: str) -> bool:
    normalized = {str(item).strip().lower() for item in directions}
    return not normalized or "all" in normalized or "both" in normalized or direction in normalized


def _split_names(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _coerce_names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return _split_names(value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _case_insensitive_get(headers: Mapping[str, str], name: str) -> str:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return str(value)
    return ""


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
