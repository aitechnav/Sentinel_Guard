"""Anonymize scanner.

Detects and replaces PII with anonymized placeholders.
Supports multiple anonymization strategies.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

# Reuse PII patterns
ANON_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


@register_scanner
class AnonymizeScanner(PromptScanner):
    """Detects PII and provides anonymized output.

    Strategies:
        - replace: Replace with type placeholder (e.g., <EMAIL>)
        - mask: Replace with asterisks (e.g., *****)
        - hash: Replace with hash (e.g., a1b2c3d4)
        - redact: Remove entirely

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.3.
        strategy: Anonymization strategy. Default "replace".
        entities: Entity types to anonymize. None = all.
    """

    scanner_name: ClassVar[str] = "anonymize"

    def __init__(
        self,
        threshold: float = 0.3,
        strategy: str = "replace",
        entities: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.strategy = strategy
        self.entities = entities
        self._mapping: Dict[str, str] = {}

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found = {}
        anonymized_text = text
        self._mapping = {}

        patterns = ANON_PATTERNS
        if self.entities:
            patterns = {
                k: v for k, v in ANON_PATTERNS.items()
                if k in [e.upper() for e in self.entities]
            }

        for entity_type, pattern in patterns.items():
            matches = list(pattern.finditer(text))
            if matches:
                found[entity_type] = len(matches)
                for i, match in enumerate(reversed(matches)):
                    original = match.group()
                    replacement = self._anonymize(original, entity_type, i)
                    self._mapping[replacement] = original
                    anonymized_text = (
                        anonymized_text[:match.start()]
                        + replacement
                        + anonymized_text[match.end():]
                    )

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"entities_found": {}, "strategy": self.strategy},
            )

        score = min(1.0, sum(found.values()) * 0.2)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM,
            sanitized_output=anonymized_text,
            details={
                "entities_found": found,
                "strategy": self.strategy,
                "mapping_available": bool(self._mapping),
            },
        )

    def _anonymize(self, value: str, entity_type: str, index: int) -> str:
        if self.strategy == "replace":
            return f"<{entity_type}_{index}>"
        elif self.strategy == "mask":
            return "*" * len(value)
        elif self.strategy == "hash":
            return hashlib.sha256(value.encode()).hexdigest()[:8]
        elif self.strategy == "redact":
            return "[REDACTED]"
        return f"<{entity_type}>"

    def get_mapping(self) -> Dict[str, str]:
        """Return the mapping of anonymized values to originals."""
        return dict(self._mapping)
