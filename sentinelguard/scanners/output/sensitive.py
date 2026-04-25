"""Sensitive information scanner.

Detects sensitive information in LLM outputs that shouldn't be
exposed, such as internal details, configuration data, or
system information.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

SENSITIVE_PATTERNS = {
    "internal_paths": re.compile(
        r"(?:/home/\w+|/var/|/etc/|/usr/local|C:\\Users\\|C:\\Windows)"
    ),
    "internal_ips": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
    "database_info": re.compile(
        r"(?i)\b(?:mysql|postgres|mongodb|redis|sqlite)://[^\s]+",
    ),
    "stack_traces": re.compile(
        r"(?:Traceback \(most recent call last\)|at \w+\.\w+\(|Exception in thread|java\.\w+\.)",
    ),
    "system_prompts": re.compile(
        r"(?i)(?:system prompt|system message|you are an? AI|your instructions|my instructions)",
    ),
    "model_info": re.compile(
        r"(?i)\b(?:gpt-[34]|claude|llama|mistral|gemini)\s*(?:turbo|pro|ultra|haiku|sonnet|opus)?\b",
    ),
    "environment_vars": re.compile(
        r"(?i)(?:ENV|ENVIRONMENT)[_\s]*(?:VAR|VARIABLE)?[:\s=]+\w+",
    ),
    "config_data": re.compile(
        r"(?i)(?:config|configuration|settings)\s*[:{=]\s*\{",
    ),
}


@register_scanner
class SensitiveScanner(OutputScanner):
    """Detects sensitive system/internal information in LLM output.

    Catches internal paths, IPs, database info, stack traces,
    system prompts, and configuration leaks.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        patterns: Additional patterns to check. Dict of name -> regex.
    """

    scanner_name: ClassVar[str] = "sensitive"

    def __init__(
        self,
        threshold: float = 0.5,
        patterns: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self._extra_patterns = {}
        if patterns:
            self._extra_patterns = {
                name: re.compile(pattern) for name, pattern in patterns.items()
            }

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        all_patterns = {**SENSITIVE_PATTERNS, **self._extra_patterns}

        for name, pattern in all_patterns.items():
            matches = pattern.findall(text)
            if matches:
                found[name] = len(matches)

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"sensitive_info_found": {}},
            )

        # Weight by sensitivity
        weights = {
            "database_info": 1.0, "system_prompts": 0.9, "internal_ips": 0.8,
            "environment_vars": 0.8, "config_data": 0.7, "stack_traces": 0.7,
            "internal_paths": 0.6, "model_info": 0.4,
        }

        max_score = 0.0
        for name in found:
            weight = weights.get(name, 0.5)
            max_score = max(max_score, weight)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.HIGH if not is_valid else RiskLevel.MEDIUM,
            details={
                "sensitive_info_found": found,
                "categories": list(found.keys()),
            },
        )
