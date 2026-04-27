"""Deanonymize scanner.

Reverses anonymization applied by the AnonymizeScanner,
restoring original PII values in the output.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class DeanonymizeScanner(OutputScanner):
    """Reverses anonymization in LLM output.

    Uses a mapping from AnonymizeScanner to restore original values.

    Args:
        threshold: Not used (always processes). Default 0.5.
        mapping: Dict mapping anonymized tokens to original values.
    """

    scanner_name: ClassVar[str] = "deanonymize"

    def __init__(
        self,
        threshold: float = 0.5,
        mapping: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.mapping = mapping or {}

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        # Allow mapping to be passed via kwargs
        mapping = kwargs.get("anonymize_mapping", self.mapping)

        if not mapping:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"note": "no mapping provided"},
            )

        restored_text = text
        restorations = 0

        for token, original in mapping.items():
            if token in restored_text:
                restored_text = restored_text.replace(token, original)
                restorations += 1

        return ScanResult(
            is_valid=True,
            score=0.0,
            risk_level=RiskLevel.LOW,
            sanitized_output=restored_text if restorations > 0 else None,
            details={
                "restorations": restorations,
                "tokens_in_mapping": len(mapping),
            },
        )
