"""Ban substrings scanner.

Blocks prompts containing specific banned phrases or substrings.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class BanSubstringsScanner(PromptScanner):
    """Blocks prompts containing specific banned substrings.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        substrings: List of substrings to block.
        case_sensitive: Whether matching is case-sensitive. Default False.
        match_word_boundary: Use word boundaries for matching. Default False.
    """

    scanner_name: ClassVar[str] = "ban_substrings"

    def __init__(
        self,
        threshold: float = 0.5,
        substrings: Optional[List[str]] = None,
        case_sensitive: bool = False,
        match_word_boundary: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.substrings = substrings or []
        self.case_sensitive = case_sensitive
        self.match_word_boundary = match_word_boundary

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if not self.substrings:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"note": "no substrings configured"},
            )

        check_text = text if self.case_sensitive else text.lower()
        found = []

        for substring in self.substrings:
            check_sub = substring if self.case_sensitive else substring.lower()
            if self.match_word_boundary:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                pattern = re.compile(r"\b" + re.escape(substring) + r"\b", flags)
                if pattern.search(text):
                    found.append(substring)
            else:
                if check_sub in check_text:
                    found.append(substring)

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"banned_substrings_found": []},
            )

        score = min(1.0, len(found) * 0.5)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM,
            details={
                "banned_substrings_found": found,
                "count": len(found),
            },
        )
