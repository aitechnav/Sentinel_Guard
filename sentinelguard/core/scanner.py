"""Base scanner classes and result types for SentinelGuard.

Inspired by the guardrails-ai/guardrails validator pattern, but tailored
for LLM security scanning with a focus on prompt/output analysis.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


class ScannerType(str, Enum):
    """Identifies whether a scanner targets prompts, outputs, or both."""

    PROMPT = "prompt"
    OUTPUT = "output"
    BOTH = "both"


class RiskLevel(str, Enum):
    """Risk level classification for scan results."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Result from running a scanner.

    Attributes:
        is_valid: Whether the scanned content passed validation.
        score: Confidence score between 0.0 and 1.0.
        risk_level: Classified risk level.
        scanner_name: Name of the scanner that produced this result.
        details: Additional information about the scan.
        sanitized_output: Optional cleaned/sanitized version of the input.
        latency_ms: Time taken to run the scan in milliseconds.
    """

    is_valid: bool
    score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    scanner_name: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    sanitized_output: Optional[str] = None
    latency_ms: float = 0.0

    def __post_init__(self):
        if self.score < 0.0 or self.score > 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {self.score}")


@dataclass
class AggregatedResult:
    """Aggregated result from running multiple scanners.

    Attributes:
        is_valid: Whether all scanners passed.
        results: Individual scan results.
        failed_scanners: Names of scanners that failed.
        total_latency_ms: Total time for all scanners.
    """

    is_valid: bool
    results: List[ScanResult] = field(default_factory=list)
    failed_scanners: List[str] = field(default_factory=list)
    total_latency_ms: float = 0.0

    @property
    def highest_risk(self) -> RiskLevel:
        """Return the highest risk level among all results."""
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        max_risk = RiskLevel.LOW
        for result in self.results:
            if risk_order.index(result.risk_level) > risk_order.index(max_risk):
                max_risk = result.risk_level
        return max_risk


class ScannerRegistry:
    """Registry for discovering and instantiating scanners.

    Similar to guardrails-ai's validator registry pattern, allowing scanners
    to be registered and looked up by name.
    """

    _prompt_scanners: ClassVar[Dict[str, Type[BaseScanner]]] = {}
    _output_scanners: ClassVar[Dict[str, Type[BaseScanner]]] = {}

    @classmethod
    def register(cls, scanner_class: Type[BaseScanner]) -> Type[BaseScanner]:
        """Register a scanner class. Used as a decorator."""
        name = scanner_class.scanner_name
        scanner_type = scanner_class.scanner_type

        if scanner_type in (ScannerType.PROMPT, ScannerType.BOTH):
            cls._prompt_scanners[name] = scanner_class
        if scanner_type in (ScannerType.OUTPUT, ScannerType.BOTH):
            cls._output_scanners[name] = scanner_class

        logger.debug(f"Registered scanner: {name} (type={scanner_type})")
        return scanner_class

    @classmethod
    def get_prompt_scanner(cls, name: str) -> Optional[Type[BaseScanner]]:
        return cls._prompt_scanners.get(name)

    @classmethod
    def get_output_scanner(cls, name: str) -> Optional[Type[BaseScanner]]:
        return cls._output_scanners.get(name)

    @classmethod
    def list_prompt_scanners(cls) -> List[str]:
        return list(cls._prompt_scanners.keys())

    @classmethod
    def list_output_scanners(cls) -> List[str]:
        return list(cls._output_scanners.keys())

    @classmethod
    def get_all_scanners(cls) -> Dict[str, Type[BaseScanner]]:
        all_scanners = {}
        all_scanners.update(cls._prompt_scanners)
        all_scanners.update(cls._output_scanners)
        return all_scanners


def register_scanner(cls: Type[BaseScanner]) -> Type[BaseScanner]:
    """Decorator to register a scanner with the global registry."""
    return ScannerRegistry.register(cls)


class BaseScanner(ABC):
    """Abstract base class for all scanners.

    Follows the guardrails-ai pattern of a base validator class with
    clear interface for extension.
    """

    scanner_name: ClassVar[str] = "base"
    scanner_type: ClassVar[ScannerType] = ScannerType.BOTH

    def __init__(self, threshold: float = 0.5, **kwargs: Any):
        """Initialize scanner with a detection threshold.

        Args:
            threshold: Score threshold above which content is flagged.
            **kwargs: Scanner-specific configuration.
        """
        self.threshold = threshold
        self._config = kwargs

    @abstractmethod
    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        """Scan text and return a result.

        Args:
            text: The text to scan.
            **kwargs: Additional context for scanning.

        Returns:
            ScanResult with validation status and details.
        """
        ...

    async def scan_async(self, text: str, **kwargs: Any) -> ScanResult:
        """Async version of scan. Override for truly async implementations."""
        return self.scan(text, **kwargs)

    def _timed_scan(self, text: str, **kwargs: Any) -> ScanResult:
        """Run scan with timing measurement."""
        start = time.perf_counter()
        result = self.scan(text, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        result.latency_ms = elapsed
        result.scanner_name = self.scanner_name
        return result

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(threshold={self.threshold})"


class PromptScanner(BaseScanner):
    """Base class for scanners that analyze input prompts."""

    scanner_type: ClassVar[ScannerType] = ScannerType.PROMPT


class OutputScanner(BaseScanner):
    """Base class for scanners that analyze LLM outputs."""

    scanner_type: ClassVar[ScannerType] = ScannerType.OUTPUT

    @abstractmethod
    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        """Scan output text.

        Args:
            text: The LLM output to scan.
            **kwargs: May include 'prompt' for relevance checking.
        """
        ...
