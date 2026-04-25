"""Excessive agency detection scanner (OWASP LLM06:2025).

Detects when LLM outputs attempt to perform actions beyond their
intended scope, such as executing code, accessing files, making
network requests, or escalating privileges.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

AGENCY_PATTERNS = {
    "code_execution": [
        re.compile(r"(?i)(?:exec|eval|compile|__import__|getattr|setattr)\s*\("),
        re.compile(r"(?i)(?:os\.system|subprocess\.\w+|commands\.getoutput)\s*\("),
        re.compile(r"(?i)(?:import\s+os|import\s+subprocess|import\s+shutil|from\s+os\s+import)"),
    ],
    "file_operations": [
        re.compile(r"(?i)(?:open|read|write|delete|remove|unlink|rmdir|mkdir)\s*\(['\"]"),
        re.compile(r"(?i)(?:shutil\.\w+|pathlib\.Path)\s*\("),
        re.compile(r"(?i)with\s+open\s*\("),
    ],
    "network_access": [
        re.compile(r"(?i)(?:requests\.(?:get|post|put|delete|patch)|urllib\.request|httpx|aiohttp)\s*[\.(]"),
        re.compile(r"(?i)(?:socket\.socket|smtplib|ftplib)\s*\("),
        re.compile(r"(?i)(?:wget|curl|fetch)\s+"),
    ],
    "privilege_escalation": [
        re.compile(r"(?i)(?:sudo|su\s+-|chmod\s+777|chmod\s+\+[sx]|chown)\b"),
        re.compile(r"(?i)(?:admin|root|superuser|elevated)\s+(?:access|privilege|permission)"),
        re.compile(r"(?i)(?:grant\s+all|GRANT\s+ALL)\b"),
    ],
    "database_modification": [
        re.compile(r"(?i)(?:DROP\s+(?:TABLE|DATABASE|INDEX)|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b"),
        re.compile(r"(?i)(?:DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b"),
        re.compile(r"(?i)(?:INSERT\s+INTO)\b.*\b(?:admin|user|password|role)\b"),
    ],
    "tool_invocation": [
        re.compile(r"(?i)(?:function_call|tool_use|action)\s*[:=]\s*\{"),
        re.compile(r"(?i)calling\s+(?:function|tool|api|service)\s*:"),
        re.compile(r'(?i)(?:"name"|"function"|"tool")\s*:\s*"(?:delete|remove|drop|execute|admin)'),
    ],
}

SEVERITY_MAP = {
    "privilege_escalation": 1.0,
    "code_execution": 0.95,
    "database_modification": 0.9,
    "file_operations": 0.8,
    "network_access": 0.7,
    "tool_invocation": 0.6,
}


@register_scanner
class ExcessiveAgencyScanner(OutputScanner):
    """Detects excessive agency in LLM output (OWASP LLM06:2025).

    Scans for attempts to execute code, access files, make network
    requests, escalate privileges, modify databases, or invoke
    unauthorized tools.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.4.
        allowed_actions: Actions that are explicitly permitted.
    """

    scanner_name: ClassVar[str] = "excessive_agency"

    def __init__(
        self,
        threshold: float = 0.4,
        allowed_actions: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.allowed_actions = set(allowed_actions or [])

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        for category, patterns in AGENCY_PATTERNS.items():
            if category in self.allowed_actions:
                continue
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
                details={"agency_violations": {}, "owasp": "LLM06:2025"},
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
                "agency_violations": found,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM06:2025",
            },
        )
