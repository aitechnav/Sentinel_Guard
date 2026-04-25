"""Configuration system for SentinelGuard.

Supports YAML/JSON configuration files and programmatic configuration.
Inspired by guardrails-ai's Settings singleton pattern.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

logger = logging.getLogger(__name__)


class GuardMode(str, Enum):
    """Operating mode for the guard."""

    PERMISSIVE = "permissive"  # Log warnings but allow through
    STANDARD = "standard"  # Block high-risk content
    STRICT = "strict"  # Block anything suspicious


@dataclass
class ScannerConfig:
    """Configuration for an individual scanner.

    Attributes:
        enabled: Whether this scanner is active.
        threshold: Detection sensitivity (0.0-1.0).
        params: Scanner-specific parameters.
        on_fail: Action to take on failure ('block', 'warn', 'sanitize').
    """

    enabled: bool = True
    threshold: float = 0.5
    params: Dict[str, Any] = field(default_factory=dict)
    on_fail: str = "block"


@dataclass
class GuardConfig:
    """Main configuration for SentinelGuard.

    Attributes:
        mode: Operating mode (permissive, standard, strict).
        fail_fast: Stop on first scanner failure.
        parallel: Run scanners in parallel.
        max_workers: Max parallel workers.
        prompt_scanners: Configuration for prompt scanners.
        output_scanners: Configuration for output scanners.
        log_level: Logging level.
    """

    mode: GuardMode = GuardMode.STANDARD
    fail_fast: bool = False
    parallel: bool = True
    max_workers: int = 4
    prompt_scanners: Dict[str, ScannerConfig] = field(default_factory=dict)
    output_scanners: Dict[str, ScannerConfig] = field(default_factory=dict)
    log_level: str = "INFO"

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> GuardConfig:
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardConfig:
        """Create configuration from a dictionary."""
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> GuardConfig:
        mode = GuardMode(data.get("mode", "standard"))
        fail_fast = data.get("fail_fast", False)
        parallel = data.get("parallel", True)
        max_workers = data.get("max_workers", 4)
        log_level = data.get("log_level", "INFO")

        prompt_scanners = {}
        for name, cfg in data.get("prompt_scanners", {}).items():
            if isinstance(cfg, dict):
                prompt_scanners[name] = ScannerConfig(**cfg)
            elif isinstance(cfg, bool):
                prompt_scanners[name] = ScannerConfig(enabled=cfg)

        output_scanners = {}
        for name, cfg in data.get("output_scanners", {}).items():
            if isinstance(cfg, dict):
                output_scanners[name] = ScannerConfig(**cfg)
            elif isinstance(cfg, bool):
                output_scanners[name] = ScannerConfig(enabled=cfg)

        return cls(
            mode=mode,
            fail_fast=fail_fast,
            parallel=parallel,
            max_workers=max_workers,
            prompt_scanners=prompt_scanners,
            output_scanners=output_scanners,
            log_level=log_level,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration to a dictionary."""
        return {
            "mode": self.mode.value,
            "fail_fast": self.fail_fast,
            "parallel": self.parallel,
            "max_workers": self.max_workers,
            "log_level": self.log_level,
            "prompt_scanners": {
                name: {
                    "enabled": cfg.enabled,
                    "threshold": cfg.threshold,
                    "params": cfg.params,
                    "on_fail": cfg.on_fail,
                }
                for name, cfg in self.prompt_scanners.items()
            },
            "output_scanners": {
                name: {
                    "enabled": cfg.enabled,
                    "threshold": cfg.threshold,
                    "params": cfg.params,
                    "on_fail": cfg.on_fail,
                }
                for name, cfg in self.output_scanners.items()
            },
        }

    def save_yaml(self, path: Union[str, Path]) -> None:
        """Save configuration to a YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)

    @classmethod
    def preset_minimal(cls) -> GuardConfig:
        """Minimal configuration with only essential scanners."""
        return cls(
            mode=GuardMode.STANDARD,
            prompt_scanners={
                "prompt_injection": ScannerConfig(enabled=True, threshold=0.7),
                "pii": ScannerConfig(enabled=True, threshold=0.5),
                "toxicity": ScannerConfig(enabled=True, threshold=0.7),
            },
            output_scanners={
                "pii": ScannerConfig(enabled=True, threshold=0.5),
                "toxicity": ScannerConfig(enabled=True, threshold=0.7),
            },
        )

    @classmethod
    def preset_strict(cls) -> GuardConfig:
        """Strict configuration with all scanners enabled at low thresholds."""
        return cls(
            mode=GuardMode.STRICT,
            fail_fast=True,
            prompt_scanners={
                "prompt_injection": ScannerConfig(enabled=True, threshold=0.5),
                "pii": ScannerConfig(enabled=True, threshold=0.3),
                "secrets": ScannerConfig(enabled=True, threshold=0.3),
                "toxicity": ScannerConfig(enabled=True, threshold=0.5),
                "gibberish": ScannerConfig(enabled=True, threshold=0.7),
                "invisible_text": ScannerConfig(enabled=True, threshold=0.1),
                "code": ScannerConfig(enabled=True, threshold=0.5),
                "ban_topics": ScannerConfig(enabled=True, threshold=0.5),
                "token_limit": ScannerConfig(enabled=True, params={"max_tokens": 4096}),
            },
            output_scanners={
                "pii": ScannerConfig(enabled=True, threshold=0.3),
                "toxicity": ScannerConfig(enabled=True, threshold=0.5),
                "bias": ScannerConfig(enabled=True, threshold=0.5),
                "relevance": ScannerConfig(enabled=True, threshold=0.3),
                "malicious_urls": ScannerConfig(enabled=True, threshold=0.5),
                "sensitive": ScannerConfig(enabled=True, threshold=0.5),
            },
        )


class Settings:
    """Thread-safe singleton for global SentinelGuard settings.

    Following the guardrails-ai pattern of a singleton settings object
    with thread-safe initialization.
    """

    _instance: Optional[Settings] = None
    _lock = threading.Lock()

    def __new__(cls) -> Settings:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.debug: bool = False
        self.log_level: str = "INFO"
        self.cache_models: bool = True
        self.model_cache_dir: Optional[str] = None
        self.default_config: Optional[GuardConfig] = None
        self._initialized = True

    @classmethod
    def reset(cls):
        """Reset settings to defaults (useful for testing)."""
        with cls._lock:
            cls._instance = None


settings = Settings()
