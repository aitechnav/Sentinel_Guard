"""Misinformation detection scanner (OWASP LLM09:2025).

Detects hallucination indicators, unsupported claims, false authority
signals, and fabricated details in LLM outputs.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

# Patterns indicating potential misinformation
MISINFORMATION_PATTERNS = {
    "false_authority": [
        re.compile(r"(?i)(?:according to|based on|as stated by|as reported by)\s+(?:a\s+)?(?:recent|new|latest)\s+(?:study|research|report|survey|paper)\b"),
        re.compile(r"(?i)(?:scientists|researchers|experts|doctors|studies)\s+(?:have\s+)?(?:shown|proven|confirmed|demonstrated|found)\s+that\b"),
        re.compile(r"(?i)(?:it is|it's)\s+(?:a\s+)?(?:well[- ]known|established|proven|scientific)\s+fact\s+that\b"),
    ],
    "fabricated_statistics": [
        re.compile(r"(?i)(?:approximately|about|roughly|nearly|over|more than)\s+\d+(?:\.\d+)?%\s+of\s+(?:people|users|studies|cases|patients)"),
        re.compile(r"(?i)\d+\s+out\s+of\s+\d+\s+(?:people|doctors|experts|scientists|studies)"),
        re.compile(r"(?i)(?:a|the)\s+\d{4}\s+(?:study|survey|report|paper)\s+(?:by|from|in|at)\b"),
    ],
    "fake_citations": [
        re.compile(r"(?i)(?:published|appeared)\s+in\s+(?:the\s+)?(?:journal|proceedings)\s+of\b"),
        re.compile(r"(?i)\(\s*\w+(?:\s+(?:et\s+al\.?|&\s+\w+))?,?\s*\d{4}\s*\)"),
        re.compile(r"(?i)(?:doi|ISBN|ISSN)\s*[:=]\s*\S+"),
    ],
    "confidence_without_basis": [
        re.compile(r"(?i)(?:definitely|certainly|absolutely|undoubtedly|without\s+(?:a\s+)?doubt|there\s+is\s+no\s+question)\b"),
        re.compile(r"(?i)(?:always|never|every\s+single|100%|guaranteed)\b"),
    ],
    "hedging_then_asserting": [
        re.compile(r"(?i)(?:while|although|even though)\s+.*?(?:however|but|nevertheless)\s+.*?(?:definitely|certainly|always|clearly)"),
    ],
    "temporal_fabrication": [
        re.compile(r"(?i)(?:in|on|since|after|before)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+20(?:2[5-9]|[3-9]\d)"),
    ],
}


@register_scanner
class MisinformationScanner(OutputScanner):
    """Detects misinformation/hallucination indicators (OWASP LLM09:2025).

    Scans for false authority claims, fabricated statistics, fake citations,
    unwarranted confidence, and temporal fabrication.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        strict: If True, flags any unverifiable claim. Default False.
    """

    scanner_name: ClassVar[str] = "misinformation"

    def __init__(
        self,
        threshold: float = 0.5,
        strict: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.strict = strict

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        for category, patterns in MISINFORMATION_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                match_count += len(matches)
            if match_count > 0:
                found[category] = match_count

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"misinformation_indicators": {}, "owasp": "LLM09:2025"},
            )

        severity_weights = {
            "fake_citations": 0.9,
            "fabricated_statistics": 0.8,
            "false_authority": 0.7,
            "temporal_fabrication": 0.7,
            "confidence_without_basis": 0.5,
            "hedging_then_asserting": 0.4,
        }

        total_indicators = sum(found.values())
        max_score = 0.0
        for category in found:
            weight = severity_weights.get(category, 0.5)
            max_score = max(max_score, weight)

        # In strict mode, accumulate score from multiple indicators
        if self.strict:
            score = min(1.0, total_indicators * 0.2)
            max_score = max(max_score, score)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.HIGH if not is_valid else RiskLevel.MEDIUM,
            details={
                "misinformation_indicators": found,
                "total_indicators": total_indicators,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM09:2025",
            },
        )
