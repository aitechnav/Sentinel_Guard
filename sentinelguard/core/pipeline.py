"""Scanner pipeline for orchestrating multiple scanners.

Supports both sequential and parallel execution, with fail-fast semantics
and configurable error handling.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional

from sentinelguard.core.config import GuardConfig
from sentinelguard.core.scanner import (
    AggregatedResult,
    BaseScanner,
    RiskLevel,
    ScannerRegistry,
    ScanResult,
)

logger = logging.getLogger(__name__)


class ScannerPipeline:
    """Orchestrates execution of multiple scanners.

    Supports parallel execution, fail-fast mode, and configurable
    error handling per scanner.
    """

    def __init__(
        self,
        scanners: Optional[List[BaseScanner]] = None,
        fail_fast: bool = False,
        parallel: bool = True,
        max_workers: int = 4,
    ):
        self.scanners: List[BaseScanner] = scanners or []
        self.fail_fast = fail_fast
        self.parallel = parallel
        self.max_workers = max_workers

    def add_scanner(self, scanner: BaseScanner) -> ScannerPipeline:
        """Add a scanner to the pipeline. Returns self for chaining."""
        self.scanners.append(scanner)
        return self

    def remove_scanner(self, scanner_name: str) -> ScannerPipeline:
        """Remove a scanner by name. Returns self for chaining."""
        self.scanners = [s for s in self.scanners if s.scanner_name != scanner_name]
        return self

    def run(self, text: str, **kwargs: Any) -> AggregatedResult:
        """Run all scanners against the text.

        Args:
            text: The text to scan.
            **kwargs: Additional context passed to each scanner.

        Returns:
            AggregatedResult with combined results from all scanners.
        """
        if not self.scanners:
            return AggregatedResult(is_valid=True)

        start = time.perf_counter()

        if self.parallel and len(self.scanners) > 1 and not self.fail_fast:
            results = self._run_parallel(text, **kwargs)
        else:
            results = self._run_sequential(text, **kwargs)

        total_ms = (time.perf_counter() - start) * 1000
        failed = [r.scanner_name for r in results if not r.is_valid]
        is_valid = len(failed) == 0

        return AggregatedResult(
            is_valid=is_valid,
            results=results,
            failed_scanners=failed,
            total_latency_ms=total_ms,
        )

    async def run_async(self, text: str, **kwargs: Any) -> AggregatedResult:
        """Run all scanners asynchronously."""
        if not self.scanners:
            return AggregatedResult(is_valid=True)

        start = time.perf_counter()

        if self.parallel and len(self.scanners) > 1 and not self.fail_fast:
            results = await self._run_parallel_async(text, **kwargs)
        else:
            results = await self._run_sequential_async(text, **kwargs)

        total_ms = (time.perf_counter() - start) * 1000
        failed = [r.scanner_name for r in results if not r.is_valid]

        return AggregatedResult(
            is_valid=len(failed) == 0,
            results=results,
            failed_scanners=failed,
            total_latency_ms=total_ms,
        )

    def _run_sequential(self, text: str, **kwargs: Any) -> List[ScanResult]:
        """Run scanners one at a time."""
        results = []
        for scanner in self.scanners:
            try:
                result = scanner._timed_scan(text, **kwargs)
                results.append(result)
                if self.fail_fast and not result.is_valid:
                    logger.info(
                        f"Fail-fast triggered by {scanner.scanner_name} "
                        f"(score={result.score:.3f})"
                    )
                    break
            except Exception as e:
                logger.error(f"Scanner {scanner.scanner_name} failed: {e}")
                results.append(
                    ScanResult(
                        is_valid=False,
                        score=1.0,
                        risk_level=RiskLevel.HIGH,
                        scanner_name=scanner.scanner_name,
                        details={"error": str(e)},
                    )
                )
                if self.fail_fast:
                    break
        return results

    def _run_parallel(self, text: str, **kwargs: Any) -> List[ScanResult]:
        """Run scanners in parallel using thread pool."""
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(scanner._timed_scan, text, **kwargs): scanner
                for scanner in self.scanners
            }
            for future in as_completed(futures):
                scanner = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Scanner {scanner.scanner_name} failed: {e}")
                    results.append(
                        ScanResult(
                            is_valid=False,
                            score=1.0,
                            risk_level=RiskLevel.HIGH,
                            scanner_name=scanner.scanner_name,
                            details={"error": str(e)},
                        )
                    )
        return results

    async def _run_sequential_async(self, text: str, **kwargs: Any) -> List[ScanResult]:
        """Run scanners sequentially in async mode."""
        results = []
        for scanner in self.scanners:
            try:
                start = time.perf_counter()
                result = await scanner.scan_async(text, **kwargs)
                result.latency_ms = (time.perf_counter() - start) * 1000
                result.scanner_name = scanner.scanner_name
                results.append(result)
                if self.fail_fast and not result.is_valid:
                    break
            except Exception as e:
                logger.error(f"Scanner {scanner.scanner_name} failed: {e}")
                results.append(
                    ScanResult(
                        is_valid=False,
                        score=1.0,
                        risk_level=RiskLevel.HIGH,
                        scanner_name=scanner.scanner_name,
                        details={"error": str(e)},
                    )
                )
                if self.fail_fast:
                    break
        return results

    async def _run_parallel_async(self, text: str, **kwargs: Any) -> List[ScanResult]:
        """Run scanners in parallel using asyncio."""

        async def _run_one(scanner: BaseScanner) -> ScanResult:
            try:
                start = time.perf_counter()
                result = await scanner.scan_async(text, **kwargs)
                result.latency_ms = (time.perf_counter() - start) * 1000
                result.scanner_name = scanner.scanner_name
                return result
            except Exception as e:
                logger.error(f"Scanner {scanner.scanner_name} failed: {e}")
                return ScanResult(
                    is_valid=False,
                    score=1.0,
                    risk_level=RiskLevel.HIGH,
                    scanner_name=scanner.scanner_name,
                    details={"error": str(e)},
                )

        tasks = [_run_one(scanner) for scanner in self.scanners]
        return await asyncio.gather(*tasks)

    @classmethod
    def from_config(
        cls,
        config: GuardConfig,
        scanner_type: str = "prompt",
    ) -> ScannerPipeline:
        """Create a pipeline from a GuardConfig.

        Args:
            config: The guard configuration.
            scanner_type: 'prompt' or 'output'.

        Returns:
            Configured ScannerPipeline instance.
        """
        scanner_configs = (
            config.prompt_scanners if scanner_type == "prompt" else config.output_scanners
        )

        scanners = []
        for name, scanner_cfg in scanner_configs.items():
            if not scanner_cfg.enabled:
                continue

            if scanner_type == "prompt":
                scanner_cls = ScannerRegistry.get_prompt_scanner(name)
            else:
                scanner_cls = ScannerRegistry.get_output_scanner(name)

            if scanner_cls is None:
                logger.warning(f"Scanner '{name}' not found in registry, skipping")
                continue

            scanner = scanner_cls(
                threshold=scanner_cfg.threshold,
                **scanner_cfg.params,
            )
            scanners.append(scanner)

        return cls(
            scanners=scanners,
            fail_fast=config.fail_fast,
            parallel=config.parallel,
            max_workers=config.max_workers,
        )
