"""Reading time scanner.

Estimates reading time of LLM output and flags if it exceeds
configured limits.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class ReadingTimeScanner(OutputScanner):
    """Estimates and limits reading time of LLM output.

    Args:
        threshold: Not used directly; limits are time-based.
        max_seconds: Maximum reading time in seconds. Default 300 (5 min).
        words_per_minute: Assumed reading speed. Default 200.
    """

    scanner_name: ClassVar[str] = "reading_time"

    def __init__(
        self,
        threshold: float = 0.5,
        max_seconds: int = 300,
        words_per_minute: int = 200,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.max_seconds = max_seconds
        self.words_per_minute = words_per_minute

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        word_count = len(text.split())
        reading_time_minutes = word_count / self.words_per_minute
        reading_time_seconds = reading_time_minutes * 60

        exceeded = reading_time_seconds > self.max_seconds
        ratio = reading_time_seconds / self.max_seconds if self.max_seconds > 0 else 0

        return ScanResult(
            is_valid=not exceeded,
            score=min(1.0, ratio) if exceeded else 0.0,
            risk_level=RiskLevel.LOW,
            details={
                "word_count": word_count,
                "estimated_reading_time_seconds": round(reading_time_seconds, 1),
                "estimated_reading_time_minutes": round(reading_time_minutes, 1),
                "max_seconds": self.max_seconds,
                "exceeded": exceeded,
            },
        )
