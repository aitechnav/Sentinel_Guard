"""Regex scanner.

Custom pattern matching scanner that allows users to define
their own regex patterns for detection.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional, Union

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class RegexScanner(PromptScanner):
    """Custom regex pattern matching scanner.

    Allows users to define patterns that should be detected or blocked.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        patterns: List of regex patterns or dict mapping names to patterns.
        match_type: 'deny' to block matches, 'allow' to require matches. Default 'deny'.
        case_sensitive: Whether patterns are case-sensitive. Default False.
    """

    scanner_name: ClassVar[str] = "regex"

    def __init__(
        self,
        threshold: float = 0.5,
        patterns: Optional[Union[List[str], Dict[str, str]]] = None,
        match_type: str = "deny",
        case_sensitive: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.match_type = match_type
        self.case_sensitive = case_sensitive

        flags = 0 if case_sensitive else re.IGNORECASE
        if isinstance(patterns, dict):
            self._patterns = {
                name: re.compile(pattern, flags)
                for name, pattern in patterns.items()
            }
        elif isinstance(patterns, list):
            self._patterns = {
                f"pattern_{i}": re.compile(p, flags)
                for i, p in enumerate(patterns)
            }
        else:
            self._patterns = {}

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if not self._patterns:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"note": "no patterns configured"},
            )

        matched: Dict[str, List[str]] = {}
        for name, pattern in self._patterns.items():
            matches = pattern.findall(text)
            if matches:
                matched[name] = [str(m) for m in matches[:5]]  # Limit stored matches

        if self.match_type == "deny":
            # Deny mode: matches are bad
            if not matched:
                return ScanResult(
                    is_valid=True,
                    score=0.0,
                    risk_level=RiskLevel.LOW,
                    details={"matched_patterns": {}},
                )
            score = min(1.0, len(matched) / len(self._patterns))
            is_valid = score < self.threshold
        else:
            # Allow mode: lack of matches is bad
            if len(matched) == len(self._patterns):
                return ScanResult(
                    is_valid=True,
                    score=0.0,
                    risk_level=RiskLevel.LOW,
                    details={"matched_patterns": matched},
                )
            unmatched = len(self._patterns) - len(matched)
            score = unmatched / len(self._patterns)
            is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "matched_patterns": matched,
                "match_type": self.match_type,
                "patterns_checked": len(self._patterns),
            },
        )
