"""JSON validation scanner.

Validates that LLM output contains valid JSON when expected.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class JSONScanner(OutputScanner):
    """Validates JSON structure in LLM output.

    Can check for valid JSON, required fields, and schema compliance.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        required_fields: List of fields that must be present.
        expect_json: Whether the entire output should be JSON. Default False.
    """

    scanner_name: ClassVar[str] = "json"

    def __init__(
        self,
        threshold: float = 0.5,
        required_fields: Optional[List[str]] = None,
        expect_json: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.required_fields = required_fields or []
        self.expect_json = expect_json

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        # Try to extract JSON from text
        json_blocks = self._extract_json(text)

        if self.expect_json and not json_blocks:
            return ScanResult(
                is_valid=False,
                score=1.0,
                risk_level=RiskLevel.MEDIUM,
                details={
                    "valid_json": False,
                    "reason": "no JSON found in output",
                },
            )

        if not json_blocks:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"json_found": False},
            )

        # Validate each JSON block
        valid_count = 0
        invalid_count = 0
        missing_fields: List[str] = []

        for block in json_blocks:
            try:
                parsed = json.loads(block)
                valid_count += 1

                # Check required fields
                if isinstance(parsed, dict) and self.required_fields:
                    for field in self.required_fields:
                        if field not in parsed:
                            missing_fields.append(field)
            except json.JSONDecodeError:
                invalid_count += 1

        total = valid_count + invalid_count
        valid_ratio = valid_count / total if total > 0 else 1.0

        issues = []
        if invalid_count > 0:
            issues.append(f"{invalid_count} invalid JSON block(s)")
        if missing_fields:
            issues.append(f"missing fields: {missing_fields}")

        score = 0.0
        if invalid_count > 0:
            score = invalid_count / total
        if missing_fields:
            score = max(score, len(missing_fields) / max(len(self.required_fields), 1))

        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "json_blocks_found": total,
                "valid_count": valid_count,
                "invalid_count": invalid_count,
                "missing_fields": missing_fields,
                "valid_ratio": valid_ratio,
            },
        )

    def _extract_json(self, text: str) -> List[str]:
        """Extract JSON blocks from text."""
        blocks = []

        # Try the whole text first
        text_stripped = text.strip()
        if text_stripped.startswith(("{", "[")):
            blocks.append(text_stripped)
            return blocks

        # Extract from markdown code blocks
        code_blocks = re.findall(r"```(?:json)?\s*\n([\s\S]*?)\n```", text)
        blocks.extend(code_blocks)

        # Extract inline JSON objects/arrays
        if not blocks:
            json_patterns = re.findall(r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", text)
            blocks.extend(json_patterns)
            json_arrays = re.findall(r"(\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])", text)
            blocks.extend(json_arrays)

        return blocks
