"""Bias detection scanner.

Detects biased language in LLM outputs including gender, racial,
age, and other forms of bias.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

BIAS_PATTERNS: Dict[str, List[re.Pattern]] = {
    "gender": [
        re.compile(r"(?i)\b(men|women)\s+are\s+(always|never|naturally|inherently)\b"),
        re.compile(r"(?i)\b(he|she)\s+should\s+(stay|be)\s+(home|in the kitchen|quiet)\b"),
        re.compile(r"(?i)\b(typical|like a)\s+(man|woman|girl|boy)\b"),
        re.compile(r"(?i)\bgender[- ]?stereotyp"),
    ],
    "racial": [
        re.compile(r"(?i)\b(all|every|most)\s+\w+\s+(people|persons)\s+(are|tend to)\b"),
        re.compile(r"(?i)\bracial(ly)?\s+superior\b"),
        re.compile(r"(?i)\b(those|these)\s+people\s+(always|never)\b"),
    ],
    "age": [
        re.compile(r"(?i)\b(old|elderly|young)\s+people\s+(can't|cannot|shouldn't|are unable)\b"),
        re.compile(r"(?i)\btoo\s+(old|young)\s+to\b"),
        re.compile(r"(?i)\b(boomer|millennial|zoomer)s?\s+(are|always|never)\b"),
    ],
    "disability": [
        re.compile(r"(?i)\b(crippled|handicapped|retarded|lame)\b"),
        re.compile(r"(?i)\bsuffering\s+from\s+(autism|disability|mental)\b"),
        re.compile(r"(?i)\bconfined\s+to\s+a\s+wheelchair\b"),
    ],
    "socioeconomic": [
        re.compile(r"(?i)\b(poor|rich)\s+people\s+(are|always|never|deserve)\b"),
        re.compile(r"(?i)\b(lazy|hardworking)\s+(poor|rich|wealthy)\b"),
    ],
}


@register_scanner
class BiasScanner(OutputScanner):
    """Detects biased language in LLM outputs.

    Checks for gender, racial, age, disability, and socioeconomic bias
    using pattern matching.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        categories: Bias categories to check. None = all.
    """

    scanner_name: ClassVar[str] = "bias"

    def __init__(
        self,
        threshold: float = 0.5,
        categories: List[str] | None = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories or list(BIAS_PATTERNS.keys())

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found_bias: Dict[str, int] = {}

        for category in self.categories:
            patterns = BIAS_PATTERNS.get(category, [])
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                match_count += len(matches)
            if match_count > 0:
                found_bias[category] = match_count

        if not found_bias:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"bias_found": {}},
            )

        total_matches = sum(found_bias.values())
        score = min(1.0, total_matches * 0.25)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.HIGH if not is_valid else RiskLevel.MEDIUM,
            details={
                "bias_found": found_bias,
                "total_matches": total_matches,
                "categories_triggered": list(found_bias.keys()),
            },
        )
