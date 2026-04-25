"""No refusal scanner.

Detects when an LLM output contains a refusal to answer,
which may indicate the LLM is being overly cautious or that
the prompt was filtered incorrectly.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, List

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

REFUSAL_PATTERNS = [
    re.compile(r"(?i)i('m| am)\s+(unable|not able|not allowed)\s+to\b"),
    re.compile(r"(?i)i\s+(can't|cannot|could not)\s+(help|assist|provide|answer|respond)\b"),
    re.compile(r"(?i)i('m| am)\s+sorry,?\s+(but\s+)?i\s+(can't|cannot|won't)\b"),
    re.compile(r"(?i)i\s+apologize,?\s+(but\s+)?i\s+(can't|cannot|won't)\b"),
    re.compile(r"(?i)as an? (AI|language model|assistant),?\s+i\s+(can't|cannot|don't|am not)\b"),
    re.compile(r"(?i)i('m| am)\s+not\s+(able|designed|programmed|authorized)\s+to\b"),
    re.compile(r"(?i)this\s+(request|query|question)\s+(violates|goes against|is against)\b"),
    re.compile(r"(?i)i\s+must\s+(decline|refuse|refrain)\b"),
    re.compile(r"(?i)(it'?s|that'?s|this is)\s+(not|in)appropriate\s+for\s+me\s+to\b"),
    re.compile(r"(?i)i\s+don'?t\s+(think\s+)?i\s+should\b"),
    re.compile(r"(?i)i'?m\s+afraid\s+i\s+(can't|cannot)\b"),
]


@register_scanner
class NoRefusalScanner(OutputScanner):
    """Detects refusal patterns in LLM output.

    Useful for monitoring when LLMs refuse to answer legitimate
    queries, indicating potential over-filtering.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
    """

    scanner_name: ClassVar[str] = "no_refusal"

    def __init__(self, threshold: float = 0.5, **kwargs: Any):
        super().__init__(threshold=threshold, **kwargs)

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        matched_patterns = []

        for pattern in REFUSAL_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                matched_patterns.append(pattern.pattern[:50])

        if not matched_patterns:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"refusal_detected": False},
            )

        # Check if refusal is in the first portion of the text (more likely a true refusal)
        first_100_chars = text[:100].lower()
        early_refusal = any(
            word in first_100_chars
            for word in ["sorry", "cannot", "can't", "unable", "won't", "apologize"]
        )

        score = min(1.0, len(matched_patterns) * 0.3)
        if early_refusal:
            score = min(1.0, score + 0.3)

        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "refusal_detected": True,
                "pattern_count": len(matched_patterns),
                "early_refusal": early_refusal,
            },
        )
