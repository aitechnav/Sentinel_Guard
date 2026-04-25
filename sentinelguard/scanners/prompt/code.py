"""Code detection scanner.

Detects code snippets in prompts across multiple programming languages.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

CODE_PATTERNS: Dict[str, List[re.Pattern]] = {
    "python": [
        re.compile(r"\bdef\s+\w+\s*\("),
        re.compile(r"\bclass\s+\w+\s*[:\(]"),
        re.compile(r"\bimport\s+\w+"),
        re.compile(r"\bfrom\s+\w+\s+import\b"),
        re.compile(r"\bif\s+__name__\s*=="),
        re.compile(r"\bprint\s*\("),
        re.compile(r"\blambda\s+\w+\s*:"),
    ],
    "javascript": [
        re.compile(r"\bfunction\s+\w+\s*\("),
        re.compile(r"\bconst\s+\w+\s*="),
        re.compile(r"\blet\s+\w+\s*="),
        re.compile(r"\bvar\s+\w+\s*="),
        re.compile(r"=>\s*\{"),
        re.compile(r"\bconsole\.\w+\("),
        re.compile(r"\brequire\s*\(['\"]"),
    ],
    "sql": [
        re.compile(r"(?i)\bSELECT\s+.+\s+FROM\b"),
        re.compile(r"(?i)\bINSERT\s+INTO\b"),
        re.compile(r"(?i)\bUPDATE\s+\w+\s+SET\b"),
        re.compile(r"(?i)\bDELETE\s+FROM\b"),
        re.compile(r"(?i)\bDROP\s+TABLE\b"),
        re.compile(r"(?i)\bCREATE\s+TABLE\b"),
        re.compile(r"(?i)\bALTER\s+TABLE\b"),
    ],
    "shell": [
        re.compile(r"(?m)^#!/bin/(ba)?sh"),
        re.compile(r"\b(sudo|chmod|chown|wget|curl)\s+"),
        re.compile(r"\brm\s+-[rf]+\b"),
        re.compile(r"\bpipe\s*\|"),
        re.compile(r"&&\s*\w+"),
    ],
    "html": [
        re.compile(r"<script[\s>]"),
        re.compile(r"<iframe[\s>]"),
        re.compile(r"<form[\s>]"),
        re.compile(r"<img\s+[^>]*onerror"),
        re.compile(r"<\w+\s+on\w+\s*="),
    ],
    "java": [
        re.compile(r"\bpublic\s+(static\s+)?class\s+\w+"),
        re.compile(r"\bpublic\s+static\s+void\s+main"),
        re.compile(r"\bSystem\.out\.print"),
        re.compile(r"\bnew\s+\w+\s*\("),
    ],
    "cpp": [
        re.compile(r"#include\s*<\w+"),
        re.compile(r"\bstd::\w+"),
        re.compile(r"\bint\s+main\s*\("),
        re.compile(r"\bcout\s*<<"),
    ],
}


@register_scanner
class CodeScanner(PromptScanner):
    """Detects code snippets in text across multiple languages.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        languages: Languages to detect. None = all.
        block_dangerous: Extra sensitivity for SQL/shell. Default True.
    """

    scanner_name: ClassVar[str] = "code"

    def __init__(
        self,
        threshold: float = 0.5,
        languages: Optional[List[str]] = None,
        block_dangerous: bool = True,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.languages = languages
        self.block_dangerous = block_dangerous

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        detected_languages: Dict[str, int] = {}

        patterns_to_check = CODE_PATTERNS
        if self.languages:
            patterns_to_check = {
                k: v for k, v in CODE_PATTERNS.items()
                if k in self.languages
            }

        for language, patterns in patterns_to_check.items():
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                match_count += len(matches)
            if match_count > 0:
                detected_languages[language] = match_count

        if not detected_languages:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"detected_languages": {}},
            )

        # Score based on danger level
        danger_weights = {
            "sql": 0.9, "shell": 0.9, "html": 0.7,
            "python": 0.5, "javascript": 0.5, "java": 0.4,
            "cpp": 0.4,
        }

        max_score = 0.0
        for lang, count in detected_languages.items():
            weight = danger_weights.get(lang, 0.5)
            if self.block_dangerous and lang in ("sql", "shell"):
                weight = 1.0
            lang_score = min(1.0, count * 0.2 * weight)
            max_score = max(max_score, lang_score)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=self._score_to_risk(max_score),
            details={
                "detected_languages": detected_languages,
                "has_dangerous_code": any(
                    lang in detected_languages for lang in ("sql", "shell")
                ),
            },
        )

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.HIGH
        elif score >= 0.5:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
