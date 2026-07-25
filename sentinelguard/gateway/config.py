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
    upstream_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    api_key: Optional[str] = None
    enabled: bool = True
    private: bool = False
    priority: int = 100
    weight: int = 1
    timeout_seconds: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProviderConfig:
        known_fields = cls.__dataclass_fields__
        return cls(**{key: value for key, value in data.items() if key in known_fields})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "upstream_url": self.upstream_url,
            "api_key_env": self.api_key_env,
            "api_key": self.api_key,
            "enabled": self.enabled,
            "private": self.private,
            "priority": self.priority,
            "weight": self.weight,
            "timeout_seconds": self.timeout_seconds,
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
    failover_status_codes: List[int] = field(
        default_factory=lambda: [408, 409, 425, 429, 500, 502, 503, 504]
    )
    timeout_seconds: float = 60.0
    default_max_tokens: int = 1024
    anthropic_version: str = "2023-06-01"
    streaming_mode: str = "buffered"
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
        known_fields = cls.__dataclass_fields__
        return cls(
            providers=providers,
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
            "client_api_key_env": self.client_api_key_env,
            "client_api_key": self.client_api_key,
            "forward_authorization": self.forward_authorization,
            "block_on_prompt_fail": self.block_on_prompt_fail,
            "block_on_output_fail": self.block_on_output_fail,
            "sanitize": self.sanitize,
            "redact_pii": self.redact_pii,
            "redact_output_pii": self.redact_output_pii,
            "route_pii_to_private_provider": self.route_pii_to_private_provider,
            "fallback_enabled": self.fallback_enabled,
            "failover_status_codes": list(self.failover_status_codes),
            "timeout_seconds": self.timeout_seconds,
            "default_max_tokens": self.default_max_tokens,
            "anthropic_version": self.anthropic_version,
            "streaming_mode": self.streaming_mode,
            "metrics_enabled": self.metrics_enabled,
            "audit_enabled": self.audit_enabled,
            "audit_hash_salt_env": self.audit_hash_salt_env,
        }
