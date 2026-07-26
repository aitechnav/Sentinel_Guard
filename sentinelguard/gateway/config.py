"""Configuration for the SentinelGuard LLM gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml


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
            "api_key": self.api_key,
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
    max_requests: Optional[int] = None
    max_tokens: Optional[int] = None
    max_budget: Optional[float] = None
    budget_reset: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VirtualKeyConfig:
        known_fields = cls.__dataclass_fields__
        return cls(**{key: value for key, value in data.items() if key in known_fields})

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
            "max_requests": self.max_requests,
            "max_tokens": self.max_tokens,
            "max_budget": self.max_budget,
            "budget_reset": self.budget_reset,
        }


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
    fallback_enabled: bool = True
    routing_strategy: str = "priority"
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
        known_fields = cls.__dataclass_fields__
        return cls(
            providers=providers,
            virtual_keys=virtual_keys,
            **{key: value for key, value in gateway_data.items() if key in known_fields},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "upstream_url": self.upstream_url,
            "api_key_env": self.api_key_env,
            "api_key": self.api_key,
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
            "fallback_enabled": self.fallback_enabled,
            "routing_strategy": self.routing_strategy,
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
            "otel_enabled": self.otel_enabled,
            "langfuse_enabled": self.langfuse_enabled,
            "metrics_enabled": self.metrics_enabled,
            "audit_enabled": self.audit_enabled,
            "audit_hash_salt_env": self.audit_hash_salt_env,
        }
