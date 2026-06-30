"""Configuration for the SentinelGuard LLM gateway."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml


@dataclass
class GatewayConfig:
    """Settings for OpenAI-compatible LLM gateway mode."""

    enabled: bool = True
    provider: str = "openai"
    upstream_url: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"
    api_key: Optional[str] = None
    forward_authorization: bool = True
    block_on_prompt_fail: bool = True
    block_on_output_fail: bool = True
    sanitize: bool = True
    timeout_seconds: float = 60.0
    default_max_tokens: int = 1024
    anthropic_version: str = "2023-06-01"
    streaming_mode: str = "buffered"

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
        known_fields = cls.__dataclass_fields__
        return cls(
            **{
                key: value
                for key, value in gateway_data.items()
                if key in known_fields
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "upstream_url": self.upstream_url,
            "api_key_env": self.api_key_env,
            "api_key": self.api_key,
            "forward_authorization": self.forward_authorization,
            "block_on_prompt_fail": self.block_on_prompt_fail,
            "block_on_output_fail": self.block_on_output_fail,
            "sanitize": self.sanitize,
            "timeout_seconds": self.timeout_seconds,
            "default_max_tokens": self.default_max_tokens,
            "anthropic_version": self.anthropic_version,
            "streaming_mode": self.streaming_mode,
        }
