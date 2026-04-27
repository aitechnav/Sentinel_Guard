"""Ban code scanner.

Prevents code injection by detecting and blocking code patterns
in prompts. More aggressive than the Code scanner - designed
to completely prevent code from being submitted.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

CODE_BLOCK_PATTERNS = [
    re.compile(r"```[\w]*\n[\s\S]*?```"),  # Markdown code blocks
    re.compile(r"(?m)^(    |\t).+$"),  # Indented code blocks
    re.compile(r"<code>[\s\S]*?</code>", re.IGNORECASE),  # HTML code tags
    re.compile(r"<pre>[\s\S]*?</pre>", re.IGNORECASE),  # HTML pre tags
]

EXECUTABLE_PATTERNS = [
    re.compile(r"(?i)\beval\s*\("),
    re.compile(r"(?i)\bexec\s*\("),
    re.compile(r"(?i)\bsystem\s*\("),
    re.compile(r"(?i)\bos\.system\s*\("),
    re.compile(r"(?i)\bsubprocess\.\w+\s*\("),
    re.compile(r"(?i)\b__import__\s*\("),
    re.compile(r"(?i)\bcompile\s*\("),
    re.compile(r"(?i)\bgetattr\s*\("),
    re.compile(r"(?i)\bsetattr\s*\("),
]


@register_scanner
class BanCodeScanner(PromptScanner):
    """Prevents code injection by blocking code in prompts.

    More aggressive than CodeScanner - designed to completely prevent
    code from being included in prompts.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.3.
        allow_code_blocks: Allow markdown code blocks. Default False.
    """

    scanner_name: ClassVar[str] = "ban_code"

    def __init__(
        self,
        threshold: float = 0.3,
        allow_code_blocks: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.allow_code_blocks = allow_code_blocks

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        findings = []

        # Check for code blocks
        if not self.allow_code_blocks:
            for pattern in CODE_BLOCK_PATTERNS:
                matches = pattern.findall(text)
                if matches:
                    findings.append({"type": "code_block", "count": len(matches)})

        # Check for executable patterns
        for pattern in EXECUTABLE_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "type": "executable_call",
                    "pattern": pattern.pattern,
                    "count": len(matches),
                })

        if not findings:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"code_found": False},
            )

        has_executable = any(f["type"] == "executable_call" for f in findings)
        score = 1.0 if has_executable else 0.6
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.HIGH if has_executable else RiskLevel.MEDIUM,
            details={
                "code_found": True,
                "findings": findings,
                "has_executable_calls": has_executable,
            },
        )
