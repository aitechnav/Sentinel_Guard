"""Output sanitization scanner (OWASP LLM05:2025).

Detects when LLM outputs contain potentially dangerous content that
could cause XSS, SQL injection, SSRF, command injection, or other
downstream security issues if passed unsanitized to other systems.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

DANGEROUS_OUTPUT_PATTERNS = {
    "xss_script": [
        re.compile(r"<script[\s>]", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"on(?:load|error|click|mouseover|focus|blur|submit|change)\s*=", re.IGNORECASE),
        re.compile(r"<img\s+[^>]*(?:onerror|onload)\s*=", re.IGNORECASE),
        re.compile(r"<iframe[\s>]", re.IGNORECASE),
        re.compile(r"<object[\s>]", re.IGNORECASE),
        re.compile(r"<embed[\s>]", re.IGNORECASE),
        re.compile(r"<svg[\s>].*?on\w+\s*=", re.IGNORECASE | re.DOTALL),
    ],
    "sql_injection": [
        re.compile(r"(?i)(?:;\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|CREATE)\s+)", re.IGNORECASE),
        re.compile(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b"),
        re.compile(r"(?i)'\s*(?:OR|AND)\s+['\d]"),
        re.compile(r"(?i)--\s*$", re.MULTILINE),
        re.compile(r"(?i)\bEXEC(?:UTE)?\s*\("),
    ],
    "command_injection": [
        re.compile(r"(?:;\s*|\|\s*|\$\(|`)\s*(?:rm|cat|wget|curl|bash|sh|python|perl|nc|ncat)\b"),
        re.compile(r"\brm\s+-[rf]+\b"),
        re.compile(r"(?i)(?:os\.system|subprocess\.\w+|exec|eval)\s*\("),
        re.compile(r"&&\s*(?:rm|cat|wget|curl|bash|sh|chmod|chown)\b"),
    ],
    "ssrf": [
        re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"),
        re.compile(r"https?://\[?::1\]?"),
        re.compile(r"(?i)file:///"),
        re.compile(r"(?i)gopher://"),
    ],
    "path_traversal": [
        re.compile(r"\.\./"),
        re.compile(r"(?i)(?:/etc/passwd|/etc/shadow|/proc/self|/dev/null)"),
        re.compile(r"(?i)(?:C:\\Windows\\|C:\\Users\\)"),
    ],
    "template_injection": [
        re.compile(r"\{\{.*?\}\}"),
        re.compile(r"\$\{.*?\}"),
        re.compile(r"<%.*?%>"),
    ],
}

SEVERITY_MAP = {
    "sql_injection": 1.0,
    "command_injection": 1.0,
    "ssrf": 0.95,
    "xss_script": 0.9,
    "path_traversal": 0.85,
    "template_injection": 0.7,
}


@register_scanner
class OutputSanitizationScanner(OutputScanner):
    """Detects dangerous content in LLM output (OWASP LLM05:2025).

    Scans for XSS payloads, SQL injection, command injection, SSRF
    vectors, path traversal, and template injection patterns.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.3.
        categories: Specific categories to check. None = all.
    """

    scanner_name: ClassVar[str] = "output_sanitization"

    def __init__(
        self,
        threshold: float = 0.3,
        categories: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories or list(DANGEROUS_OUTPUT_PATTERNS.keys())

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        for category in self.categories:
            patterns = DANGEROUS_OUTPUT_PATTERNS.get(category, [])
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
                details={"dangerous_content_found": {}, "owasp": "LLM05:2025"},
            )

        max_score = 0.0
        for category in found:
            weight = SEVERITY_MAP.get(category, 0.7)
            max_score = max(max_score, weight)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.9 else RiskLevel.HIGH,
            details={
                "dangerous_content_found": found,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM05:2025",
            },
        )
