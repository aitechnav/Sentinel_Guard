"""Main SentinelGuard class - the primary entry point for the framework.

Follows the guardrails-ai Guard pattern with fluent builder API,
but focused on security scanning rather than LLM output validation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from sentinelguard.core.config import GuardConfig, GuardMode, ScannerConfig
from sentinelguard.core.pipeline import ScannerPipeline
from sentinelguard.core.scanner import (
    AggregatedResult,
    BaseScanner,
    ScannerRegistry,
    ScanResult,
)

logger = logging.getLogger(__name__)


class SentinelGuard:
    """Main entry point for LLM security scanning.

    Provides a fluent API for configuring and running prompt/output scanners.

    Usage:
        # Simple usage with defaults
        guard = SentinelGuard()
        result = guard.scan_prompt("User input here")

        # With custom configuration
        config = GuardConfig(mode="strict")
        guard = SentinelGuard(config=config)

        # Builder pattern
        guard = SentinelGuard()
        guard.use("prompt_injection", threshold=0.7)
        guard.use("pii", threshold=0.5)
    """

    def __init__(
        self,
        config: Optional[GuardConfig] = None,
        prompt_scanners: Optional[List[BaseScanner]] = None,
        output_scanners: Optional[List[BaseScanner]] = None,
    ):
        """Initialize SentinelGuard.

        Args:
            config: Configuration object. If None, uses default config.
            prompt_scanners: Explicit list of prompt scanners.
            output_scanners: Explicit list of output scanners.
        """
        self.config = config or GuardConfig()
        self._setup_logging()

        if prompt_scanners is not None:
            self._prompt_pipeline = ScannerPipeline(
                scanners=prompt_scanners,
                fail_fast=self.config.fail_fast,
                parallel=self.config.parallel,
                max_workers=self.config.max_workers,
            )
        else:
            self._prompt_pipeline = ScannerPipeline.from_config(self.config, "prompt")

        if output_scanners is not None:
            self._output_pipeline = ScannerPipeline(
                scanners=output_scanners,
                fail_fast=self.config.fail_fast,
                parallel=self.config.parallel,
                max_workers=self.config.max_workers,
            )
        else:
            self._output_pipeline = ScannerPipeline.from_config(self.config, "output")

    def _setup_logging(self):
        logging.basicConfig(level=getattr(logging, self.config.log_level, logging.INFO))

    # ── Builder API (inspired by guardrails-ai Guard.use()) ──

    def use(
        self,
        scanner_name: str,
        on: str = "prompt",
        threshold: float = 0.5,
        **kwargs: Any,
    ) -> SentinelGuard:
        """Add a scanner by name. Returns self for chaining.

        Args:
            scanner_name: Name of the registered scanner.
            on: Target - 'prompt', 'output', or 'both'.
            threshold: Detection threshold.
            **kwargs: Scanner-specific parameters.

        Returns:
            Self for method chaining.
        """
        if on in ("prompt", "both"):
            scanner_cls = ScannerRegistry.get_prompt_scanner(scanner_name)
            if scanner_cls:
                self._prompt_pipeline.add_scanner(
                    scanner_cls(threshold=threshold, **kwargs)
                )
            else:
                logger.warning(f"Prompt scanner '{scanner_name}' not found")

        if on in ("output", "both"):
            scanner_cls = ScannerRegistry.get_output_scanner(scanner_name)
            if scanner_cls:
                self._output_pipeline.add_scanner(
                    scanner_cls(threshold=threshold, **kwargs)
                )
            else:
                logger.warning(f"Output scanner '{scanner_name}' not found")

        return self

    def use_many(self, *scanners: BaseScanner, on: str = "prompt") -> SentinelGuard:
        """Add multiple scanner instances. Returns self for chaining.

        Args:
            *scanners: Scanner instances to add.
            on: Target - 'prompt', 'output', or 'both'.

        Returns:
            Self for method chaining.
        """
        for scanner in scanners:
            if on in ("prompt", "both"):
                self._prompt_pipeline.add_scanner(scanner)
            if on in ("output", "both"):
                self._output_pipeline.add_scanner(scanner)
        return self

    # ── Factory Methods ──

    @classmethod
    def from_config(cls, config: Union[GuardConfig, Dict, str]) -> SentinelGuard:
        """Create a SentinelGuard from various config sources.

        Args:
            config: GuardConfig, dict, or path to YAML file.

        Returns:
            Configured SentinelGuard instance.
        """
        if isinstance(config, str):
            guard_config = GuardConfig.from_yaml(config)
        elif isinstance(config, dict):
            guard_config = GuardConfig.from_dict(config)
        else:
            guard_config = config

        return cls(config=guard_config)

    @classmethod
    def minimal(cls) -> SentinelGuard:
        """Create a guard with minimal essential scanners."""
        return cls(config=GuardConfig.preset_minimal())

    @classmethod
    def strict(cls) -> SentinelGuard:
        """Create a guard with strict security settings."""
        return cls(config=GuardConfig.preset_strict())

    # ── Scanning Methods ──

    def scan_prompt(self, text: str, **kwargs: Any) -> AggregatedResult:
        """Scan a prompt/input for security issues.

        Args:
            text: The prompt text to scan.
            **kwargs: Additional context.

        Returns:
            AggregatedResult with combined scanner results.
        """
        logger.debug(f"Scanning prompt ({len(text)} chars)")
        result = self._prompt_pipeline.run(text, **kwargs)
        self._apply_mode(result)
        return result

    def scan_output(
        self,
        text: str,
        prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> AggregatedResult:
        """Scan an LLM output for security issues.

        Args:
            text: The output text to scan.
            prompt: Original prompt for relevance checking.
            **kwargs: Additional context.

        Returns:
            AggregatedResult with combined scanner results.
        """
        logger.debug(f"Scanning output ({len(text)} chars)")
        if prompt:
            kwargs["prompt"] = prompt
        result = self._output_pipeline.run(text, **kwargs)
        self._apply_mode(result)
        return result

    async def scan_prompt_async(self, text: str, **kwargs: Any) -> AggregatedResult:
        """Async version of scan_prompt."""
        result = await self._prompt_pipeline.run_async(text, **kwargs)
        self._apply_mode(result)
        return result

    async def scan_output_async(
        self,
        text: str,
        prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> AggregatedResult:
        """Async version of scan_output."""
        if prompt:
            kwargs["prompt"] = prompt
        result = await self._output_pipeline.run_async(text, **kwargs)
        self._apply_mode(result)
        return result

    def validate(
        self,
        prompt: str,
        output: str,
        **kwargs: Any,
    ) -> Dict[str, AggregatedResult]:
        """Validate both prompt and output in one call.

        Args:
            prompt: The input prompt.
            output: The LLM output.
            **kwargs: Additional context.

        Returns:
            Dict with 'prompt' and 'output' AggregatedResults.
        """
        return {
            "prompt": self.scan_prompt(prompt, **kwargs),
            "output": self.scan_output(output, prompt=prompt, **kwargs),
        }

    def _apply_mode(self, result: AggregatedResult) -> None:
        """Apply guard mode to results (permissive mode overrides validity)."""
        if self.config.mode == GuardMode.PERMISSIVE:
            if not result.is_valid:
                logger.warning(
                    f"Guard in permissive mode - would have blocked: "
                    f"{result.failed_scanners}"
                )
                result.is_valid = True

    # ── Introspection ──

    @property
    def prompt_scanner_names(self) -> List[str]:
        """List names of active prompt scanners."""
        return [s.scanner_name for s in self._prompt_pipeline.scanners]

    @property
    def output_scanner_names(self) -> List[str]:
        """List names of active output scanners."""
        return [s.scanner_name for s in self._output_pipeline.scanners]

    def __repr__(self) -> str:
        return (
            f"SentinelGuard(mode={self.config.mode.value}, "
            f"prompt_scanners={len(self._prompt_pipeline.scanners)}, "
            f"output_scanners={len(self._output_pipeline.scanners)})"
        )
