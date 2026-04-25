"""PII (Personally Identifiable Information) detection scanner.

Detects personal information using regex patterns and optional Presidio
integration for enterprise-grade detection with 50+ entity types.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

# Built-in PII patterns (fallback when Presidio is not available)
PII_PATTERNS = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "phone_us": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "ssn": re.compile(
        r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"
    ),
    "credit_card": re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    ),
    "ip_address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "date_of_birth": re.compile(
        r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
    ),
    "passport": re.compile(
        r"\b[A-Z]{1,2}\d{6,9}\b"
    ),
    "iban": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"
    ),
    "drivers_license": re.compile(
        r"\b[A-Z]\d{7,14}\b"
    ),
    "address": re.compile(
        r"\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
        re.IGNORECASE,
    ),
}


@register_scanner
class PIIScanner(PromptScanner):
    """Detects personally identifiable information in text.

    Uses built-in regex patterns by default. When Presidio is installed,
    leverages enterprise-grade NER for 50+ entity types.

    Args:
        threshold: Confidence threshold (0.0-1.0). Default 0.5.
        entities: List of entity types to detect. None = all.
        use_presidio: Try to use Presidio if available. Default True.
        language: Language for detection. Default "en".
    """

    scanner_name: ClassVar[str] = "pii"

    def __init__(
        self,
        threshold: float = 0.5,
        entities: Optional[List[str]] = None,
        use_presidio: bool = True,
        language: str = "en",
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.entities = entities
        self.language = language
        self._use_presidio = use_presidio
        self._presidio_analyzer = None
        self._presidio_available = None

    def _check_presidio(self) -> bool:
        """Check if Presidio is available and initialize."""
        if self._presidio_available is not None:
            return self._presidio_available
        try:
            from presidio_analyzer import AnalyzerEngine

            self._presidio_analyzer = AnalyzerEngine()
            self._presidio_available = True
        except ImportError:
            self._presidio_available = False
        return self._presidio_available

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if self._use_presidio and self._check_presidio():
            return self._presidio_scan(text)
        return self._regex_scan(text)

    def _regex_scan(self, text: str) -> ScanResult:
        """Detect PII using built-in regex patterns."""
        found_entities: Dict[str, List[str]] = {}

        patterns_to_check = PII_PATTERNS
        if self.entities:
            patterns_to_check = {
                k: v for k, v in PII_PATTERNS.items()
                if k.upper() in [e.upper() for e in self.entities]
                or k in self.entities
            }

        for entity_type, pattern in patterns_to_check.items():
            matches = pattern.findall(text)
            if matches:
                found_entities[entity_type] = matches

        if not found_entities:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"method": "regex", "entities_found": {}},
            )

        # Score based on sensitivity and count
        sensitivity = {
            "ssn": 1.0, "credit_card": 1.0, "passport": 0.9,
            "drivers_license": 0.8, "iban": 0.8, "date_of_birth": 0.7,
            "email": 0.6, "phone_us": 0.6, "address": 0.6,
            "ip_address": 0.4,
        }

        max_score = 0.0
        for entity_type in found_entities:
            weight = sensitivity.get(entity_type, 0.5)
            max_score = max(max_score, weight)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=self._score_to_risk(max_score),
            details={
                "method": "regex",
                "entities_found": {k: len(v) for k, v in found_entities.items()},
                "entity_types": list(found_entities.keys()),
            },
        )

    def _presidio_scan(self, text: str) -> ScanResult:
        """Detect PII using Presidio analyzer."""
        results = self._presidio_analyzer.analyze(
            text=text,
            entities=self.entities,
            language=self.language,
        )

        if not results:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"method": "presidio", "entities_found": {}},
            )

        entities_found: Dict[str, int] = {}
        max_score = 0.0
        for result in results:
            entity_type = result.entity_type
            entities_found[entity_type] = entities_found.get(entity_type, 0) + 1
            max_score = max(max_score, result.score)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=self._score_to_risk(max_score),
            details={
                "method": "presidio",
                "entities_found": entities_found,
                "entity_types": list(entities_found.keys()),
                "total_entities": len(results),
            },
        )

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
