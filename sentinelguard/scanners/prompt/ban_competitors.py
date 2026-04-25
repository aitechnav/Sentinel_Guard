"""Ban competitors scanner.

Prevents prompts that mention competitor brands or products.
Useful for brand protection in customer-facing LLM applications.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class BanCompetitorsScanner(PromptScanner):
    """Detects and blocks mentions of competitor brands.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        competitors: List of competitor names/brands to detect.
        case_sensitive: Whether matching is case-sensitive. Default False.
    """

    scanner_name: ClassVar[str] = "ban_competitors"

    def __init__(
        self,
        threshold: float = 0.5,
        competitors: Optional[List[str]] = None,
        case_sensitive: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.competitors = competitors or []
        self.case_sensitive = case_sensitive
        flags = 0 if case_sensitive else re.IGNORECASE
        self._patterns = [
            re.compile(r"\b" + re.escape(c) + r"\b", flags)
            for c in self.competitors
        ]

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if not self.competitors:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"note": "no competitors configured"},
            )

        found_competitors = []
        for pattern, name in zip(self._patterns, self.competitors):
            if pattern.search(text):
                found_competitors.append(name)

        if not found_competitors:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"competitors_found": []},
            )

        score = min(1.0, len(found_competitors) * 0.4)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM,
            details={
                "competitors_found": found_competitors,
                "count": len(found_competitors),
            },
        )
