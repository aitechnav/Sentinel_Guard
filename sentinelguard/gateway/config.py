"""Configuration for the SentinelGuard LLM gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml


POLICY_ACTION_ALIASES = {
    "audit_only": "audit",
    "log": "audit",
    "log_only": "audit",
    "mask": "redact",
    "monitor": "audit",
    "sanitize": "redact",
    "warn": "audit",
}
POLICY_CATEGORY_ALIASES = {
    "jailbreak": "attack",
    "jailbreaks": "attack",
    "prompt_attack": "attack",
    "prompt_attacks": "attack",
    "prompt_injection": "attack",
    "prompt_injections": "attack",
    "secret": "secret",
    "secrets": "secret",
}
ALLOWED_POLICY_ACTIONS = {"allow", "audit", "block", "redact"}
ALLOWED_POLICY_CATEGORIES = {"attack", "secret", "pii", "pci", "phi", "other"}


@dataclass
class ProviderConfig:
    """One upstream model provider candidate for gateway routing."""

    name: str
    provider: str = "openai"
    model_name: Optional[str] = None
    upstream_model: Optional[str] = None
    upstream_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    api_key: Optional[str] = None
    enabled: bool = True
    private: bool = False
    priority: int = 100
    weight: int = 1
    timeout_seconds: Optional[float] = None
    input_cost_per_token: Optional[float] = None
    output_cost_per_token: Optional[float] = None
    rpm: Optional[int] = None
    tpm: Optional[int] = None
    max_parallel_requests: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProviderConfig:
        known_fields = cls.__dataclass_fields__
        return cls(**{key: value for key, value in data.items() if key in known_fields})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "model_name": self.model_name,
            "upstream_model": self.upstream_model,
            "upstream_url": self.upstream_url,
            "api_key_env": self.api_key_env,
            "api_key": "<configured>" if self.api_key else None,
            "enabled": self.enabled,
            "private": self.private,
            "priority": self.priority,
            "weight": self.weight,
            "timeout_seconds": self.timeout_seconds,
            "input_cost_per_token": self.input_cost_per_token,
            "output_cost_per_token": self.output_cost_per_token,
            "rpm": self.rpm,
            "tpm": self.tpm,
            "max_parallel_requests": self.max_parallel_requests,
        }


@dataclass
class VirtualKeyConfig:
    """One client-facing gateway key with optional access limits."""

    name: str
    key: Optional[str] = None
    key_env: Optional[str] = None
    enabled: bool = True
    tenant_id: Optional[str] = None
    team_id: Optional[str] = None
    user_id: Optional[str] = None
    allowed_models: List[str] = field(default_factory=list)
    policy_actions: Dict[str, str] = field(default_factory=dict)
    max_requests: Optional[int] = None
    max_tokens: Optional[int] = None
    max_budget: Optional[float] = None
    budget_reset: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VirtualKeyConfig:
        known_fields = cls.__dataclass_fields__
        values = {key: value for key, value in data.items() if key in known_fields}
        policy_actions = data.get("policy_actions", data.get("policy"))
        if policy_actions is not None:
            values["policy_actions"] = normalize_policy_actions(policy_actions)
        return cls(**values)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "key": "<configured>" if self.key else None,
            "key_env": self.key_env,
            "enabled": self.enabled,
            "tenant_id": self.tenant_id,
            "team_id": self.team_id,
            "user_id": self.user_id,
            "allowed_models": list(self.allowed_models),
            "policy_actions": normalize_policy_actions(self.policy_actions),
            "max_requests": self.max_requests,
            "max_tokens": self.max_tokens,
            "max_budget": self.max_budget,
            "budget_reset": self.budget_reset,
        }


@dataclass
class ComplexityRouterConfig:
    """Prompt-aware gateway routing settings."""

    enabled: bool = False
    strategy: str = "rule-based"
    auto_model_names: List[str] = field(
        default_factory=lambda: ["auto", "sentinel-auto", "sentinelguard-auto"]
    )
    simple_model: Optional[str] = None
    complex_model: Optional[str] = None
    private_model: Optional[str] = None
    default_model: Optional[str] = None
    preserve_explicit_model: bool = True
    complexity_threshold: float = 0.65

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ComplexityRouterConfig:
        known_fields = cls.__dataclass_fields__
        values = {key: value for key, value in data.items() if key in known_fields}
        auto_model_names = values.get("auto_model_names")
        if isinstance(auto_model_names, str):
            values["auto_model_names"] = [auto_model_names]
        elif auto_model_names is None:
            values.pop("auto_model_names", None)
        return cls(**values)

    def to_dict(self) -> Dict[str, Any]:
        auto_model_names = (
            [self.auto_model_names]
            if isinstance(self.auto_model_names, str)
            else list(self.auto_model_names)
        )
        return {
            "enabled": self.enabled,
            "strategy": self.strategy,
            "auto_model_names": auto_model_names,
            "simple_model": self.simple_model,
            "complex_model": self.complex_model,
            "private_model": self.private_model,
            "default_model": self.default_model,
            "preserve_explicit_model": self.preserve_explicit_model,
            "complexity_threshold": self.complexity_threshold,
        }


@dataclass
class GatewayGuardrailConfig:
    """Named gateway guardrail policy applied around LLM traffic."""

    name: str
    enabled: bool = True
    mode: str = "enforce"
    stages: List[str] = field(default_factory=lambda: ["pre_call", "post_call", "passthrough"])
    directions: List[str] = field(default_factory=lambda: ["prompt", "output", "passthrough"])
    scanners: List[str] = field(default_factory=list)
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GatewayGuardrailConfig:
        known_fields = cls.__dataclass_fields__
        values = {key: value for key, value in data.items() if key in known_fields}
        for key in ("stages", "directions", "scanners"):
            if key in values:
                values[key] = _list_value(values.get(key))
        if "mode" in values:
            values["mode"] = _normalize_guardrail_mode(values["mode"])
        return cls(**values)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "mode": _normalize_guardrail_mode(self.mode),
            "stages": list(self.stages),
            "directions": list(self.directions),
            "scanners": list(self.scanners),
            "description": self.description,
        }


def _list_value(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def normalize_policy_actions(value: Any) -> Dict[str, str]:
    """Normalize per-client gateway policy actions.

    Accepted categories are attack, secret, pii, pci, phi, and other. Actions
    are allow, audit, block, and redact. Common aliases such as secrets,
    prompt_attack, sanitize, mask, warn, and log_only are accepted.
    """
    if value is None:
        return {}
    if isinstance(value, str):
        return _policy_actions_from_string(value)
    if not isinstance(value, dict):
        return {}

    normalized: Dict[str, str] = {}
    for raw_key, raw_action in value.items():
        category = _normalize_policy_category(raw_key)
        action = _normalize_policy_action(raw_action)
        if category and action:
            normalized[category] = action
    return normalized


def _policy_actions_from_string(value: str) -> Dict[str, str]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    parsed: Dict[str, str] = {}
    for item in items:
        if ":" in item:
            key, action = item.split(":", 1)
        elif "=" in item:
            key, action = item.split("=", 1)
        else:
            continue
        category = _normalize_policy_category(key)
        normalized_action = _normalize_policy_action(action)
        if category and normalized_action:
            parsed[category] = normalized_action
    return parsed


def _normalize_policy_category(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace("-", "_")
    normalized = POLICY_CATEGORY_ALIASES.get(normalized, normalized)
    return normalized if normalized in ALLOWED_POLICY_CATEGORIES else None


def _normalize_policy_action(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace("-", "_")
    normalized = POLICY_ACTION_ALIASES.get(normalized, normalized)
    return normalized if normalized in ALLOWED_POLICY_ACTIONS else None


def _normalize_guardrail_mode(value: Any) -> str:
    normalized = str(value or "enforce").strip().lower().replace("-", "_")
    if normalized in {"log", "log_only", "logging"}:
        return "logging_only"
    if normalized not in {"enforce", "logging_only"}:
        return "enforce"
    return normalized


@dataclass
class GatewayConfig:
    """Settings for OpenAI-compatible LLM gateway mode."""

    enabled: bool = True
    provider: str = "openai"
    upstream_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    api_key: Optional[str] = None
    providers: List[ProviderConfig] = field(default_factory=list)
    virtual_keys: List[VirtualKeyConfig] = field(default_factory=list)
    client_api_key_env: Optional[str] = None
    client_api_key: Optional[str] = None
    forward_authorization: bool = True
    block_on_prompt_fail: bool = True
    block_on_output_fail: bool = True
    sanitize: bool = True
    redact_pii: bool = True
    redact_output_pii: bool = True
    route_pii_to_private_provider: bool = False
    route_sensitive_to_private_provider: bool = False
    sensitive_session_routing_enabled: bool = False
    sensitive_session_ttl_seconds: int = 1800
    sensitive_session_headers: List[str] = field(
        default_factory=lambda: [
            "x-sentinelguard-session-id",
            "x-session-id",
            "x-conversation-id",
        ]
    )
    sensitive_session_fallback_to_client: bool = False
    fallback_enabled: bool = True
    routing_strategy: str = "priority"
    complexity_router: ComplexityRouterConfig = field(default_factory=ComplexityRouterConfig)
    guardrails: List[GatewayGuardrailConfig] = field(default_factory=list)
    default_guardrail_names: List[str] = field(default_factory=list)
    guardrails_apply_endpoint_enabled: bool = True
    failover_status_codes: List[int] = field(
        default_factory=lambda: [408, 409, 425, 429, 500, 502, 503, 504]
    )
    health_check_enabled: bool = True
    unhealthy_ttl_seconds: int = 30
    timeout_seconds: float = 60.0
    default_max_tokens: int = 1024
    anthropic_version: str = "2023-06-01"
    streaming_mode: str = "buffered"
    state_backend: str = "memory"
    state_path: Optional[str] = None
    cache_backend: str = "memory"
    redis_url: Optional[str] = None
    cache_enabled: bool = False
    cache_ttl_seconds: int = 300
    cache_max_entries: int = 1024
    mcp_gateway_enabled: bool = False
    mcp_upstream_url: Optional[str] = None
    a2a_gateway_enabled: bool = False
    a2a_upstream_url: Optional[str] = None
    realtime_gateway_enabled: bool = False
    realtime_upstream_url: Optional[str] = None
    admin_ui_enabled: bool = True
    admin_auth_enabled: bool = True
    admin_state_path: Optional[str] = None
    admin_session_ttl_seconds: int = 28800
    admin_username_env: str = "SENTINELGUARD_ADMIN_USERNAME"
    admin_password_env: str = "SENTINELGUARD_ADMIN_PASSWORD"
    admin_viewer_username_env: str = "SENTINELGUARD_VIEWER_USERNAME"
    admin_viewer_password_env: str = "SENTINELGUARD_VIEWER_PASSWORD"
    provider_secret_storage_enabled: bool = True
    provider_secret_key_env: str = "SENTINELGUARD_ENCRYPTION_KEY"
    otel_enabled: bool = False
    langfuse_enabled: bool = False
    metrics_enabled: bool = True
    audit_enabled: bool = True
    audit_hash_salt_env: str = "SENTINELGUARD_AUDIT_SALT"

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> GatewayConfig:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Gateway config file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GatewayConfig:
        gateway_data = data.get("gateway", data)
        gateway_data = dict(gateway_data)
        providers = [
            ProviderConfig.from_dict(provider)
            for provider in gateway_data.pop("providers", []) or []
            if isinstance(provider, dict)
        ]
        virtual_keys = [
            VirtualKeyConfig.from_dict(virtual_key)
            for virtual_key in gateway_data.pop("virtual_keys", []) or []
            if isinstance(virtual_key, dict)
        ]
        guardrails = [
            GatewayGuardrailConfig.from_dict(guardrail)
            for guardrail in gateway_data.pop("guardrails", []) or []
            if isinstance(guardrail, dict)
        ]
        default_guardrail_names = _list_value(gateway_data.get("default_guardrail_names"))
        if default_guardrail_names:
            gateway_data["default_guardrail_names"] = default_guardrail_names
        sensitive_headers = _list_value(gateway_data.get("sensitive_session_headers"))
        if sensitive_headers:
            gateway_data["sensitive_session_headers"] = sensitive_headers
        complexity_router_data = gateway_data.pop("complexity_router", {}) or {}
        complexity_router = (
            ComplexityRouterConfig.from_dict(complexity_router_data)
            if isinstance(complexity_router_data, dict)
            else ComplexityRouterConfig()
        )
        known_fields = cls.__dataclass_fields__
        return cls(
            providers=providers,
            virtual_keys=virtual_keys,
            guardrails=guardrails,
            complexity_router=complexity_router,
            **{key: value for key, value in gateway_data.items() if key in known_fields},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "upstream_url": self.upstream_url,
            "api_key_env": self.api_key_env,
            "api_key": "<configured>" if self.api_key else None,
            "providers": [provider.to_dict() for provider in self.providers],
            "virtual_keys": [virtual_key.to_dict() for virtual_key in self.virtual_keys],
            "client_api_key_env": self.client_api_key_env,
            "client_api_key": "<configured>" if self.client_api_key else None,
            "forward_authorization": self.forward_authorization,
            "block_on_prompt_fail": self.block_on_prompt_fail,
            "block_on_output_fail": self.block_on_output_fail,
            "sanitize": self.sanitize,
            "redact_pii": self.redact_pii,
            "redact_output_pii": self.redact_output_pii,
            "route_pii_to_private_provider": self.route_pii_to_private_provider,
            "route_sensitive_to_private_provider": self.route_sensitive_to_private_provider,
            "sensitive_session_routing_enabled": self.sensitive_session_routing_enabled,
            "sensitive_session_ttl_seconds": self.sensitive_session_ttl_seconds,
            "sensitive_session_headers": list(self.sensitive_session_headers),
            "sensitive_session_fallback_to_client": self.sensitive_session_fallback_to_client,
            "fallback_enabled": self.fallback_enabled,
            "routing_strategy": self.routing_strategy,
            "complexity_router": self.complexity_router.to_dict(),
            "guardrails": [guardrail.to_dict() for guardrail in self.guardrails],
            "default_guardrail_names": list(self.default_guardrail_names),
            "guardrails_apply_endpoint_enabled": self.guardrails_apply_endpoint_enabled,
            "failover_status_codes": list(self.failover_status_codes),
            "health_check_enabled": self.health_check_enabled,
            "unhealthy_ttl_seconds": self.unhealthy_ttl_seconds,
            "timeout_seconds": self.timeout_seconds,
            "default_max_tokens": self.default_max_tokens,
            "anthropic_version": self.anthropic_version,
            "streaming_mode": self.streaming_mode,
            "state_backend": self.state_backend,
            "state_path": self.state_path,
            "cache_backend": self.cache_backend,
            "redis_url": self.redis_url,
            "cache_enabled": self.cache_enabled,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "cache_max_entries": self.cache_max_entries,
            "mcp_gateway_enabled": self.mcp_gateway_enabled,
            "mcp_upstream_url": self.mcp_upstream_url,
            "a2a_gateway_enabled": self.a2a_gateway_enabled,
            "a2a_upstream_url": self.a2a_upstream_url,
            "realtime_gateway_enabled": self.realtime_gateway_enabled,
            "realtime_upstream_url": self.realtime_upstream_url,
            "admin_ui_enabled": self.admin_ui_enabled,
            "admin_auth_enabled": self.admin_auth_enabled,
            "admin_state_path": self.admin_state_path,
            "admin_session_ttl_seconds": self.admin_session_ttl_seconds,
            "admin_username_env": self.admin_username_env,
            "admin_password_env": self.admin_password_env,
            "admin_viewer_username_env": self.admin_viewer_username_env,
            "admin_viewer_password_env": self.admin_viewer_password_env,
            "provider_secret_storage_enabled": self.provider_secret_storage_enabled,
            "provider_secret_key_env": self.provider_secret_key_env,
            "otel_enabled": self.otel_enabled,
            "langfuse_enabled": self.langfuse_enabled,
            "metrics_enabled": self.metrics_enabled,
            "audit_enabled": self.audit_enabled,
            "audit_hash_salt_env": self.audit_hash_salt_env,
        }
