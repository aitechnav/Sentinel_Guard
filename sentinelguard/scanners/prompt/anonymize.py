"""Anonymize scanner.

Detects and replaces PII with anonymized placeholders using Microsoft Presidio
(30+ entity types). Mandatory dependency — no regex fallback.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner
from sentinelguard.pii import PIIAnonymizer, PIIDetector


@register_scanner
class AnonymizeScanner(PromptScanner):
    """Detects and anonymizes PII in prompts before they reach the LLM.

    Uses Microsoft Presidio for detection (30+ entity types: EMAIL_ADDRESS,
    PHONE_NUMBER, CREDIT_CARD, US_SSN, IBAN_CODE, US_PASSPORT, IP_ADDRESS,
    PERSON, LOCATION, CRYPTO, IN_AADHAAR, AU_TFN, SG_NRIC_FIN, and more).

    Strategies:
        - replace: Replace with type placeholder, e.g. ``<EMAIL_ADDRESS>``
        - mask:    Replace with asterisks
        - hash:    Replace with a short SHA-256 hash
        - redact:  Remove entirely
        - fake:    Replace with synthetic data (requires ``faker``)

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.3.
        strategy: Default anonymization strategy. Default "replace".
        entities: Entity types to detect/anonymize. ``None`` = all available.
        language: Language hint for Presidio NLP engine. Default "en".
        entity_strategies: Per-entity-type strategy overrides, e.g.
            ``{"PHONE_NUMBER": "mask", "EMAIL_ADDRESS": "redact"}``.
        score_threshold: Minimum Presidio confidence to treat as PII.
            Default 0.5.
    """

    scanner_name: ClassVar[str] = "anonymize"

    def __init__(
        self,
        threshold: float = 0.3,
        strategy: str = "replace",
        entities: Optional[List[str]] = None,
        language: str = "en",
        entity_strategies: Optional[Dict[str, str]] = None,
        score_threshold: float = 0.5,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.strategy = strategy
        self._detector = PIIDetector(
            language=language,
            entities=entities,
            score_threshold=score_threshold,
        )
        self._anonymizer = PIIAnonymizer(
            default_strategy=strategy,
            entity_strategies=entity_strategies or {},
        )
        self._last_mapping: Dict[str, str] = {}

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        detected = self._detector.detect(text)

        if not detected:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"entities_found": {}, "strategy": self.strategy, "method": "presidio"},
            )

        anonymized = self._anonymizer.anonymize(text, detected)
        self._last_mapping = anonymized.mapping

        entity_counts: Dict[str, int] = {}
        for entity in detected:
            entity_counts[entity.entity_type] = entity_counts.get(entity.entity_type, 0) + 1

        score = min(1.0, max(e.score for e in detected))
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=self._score_to_risk(score),
            sanitized_output=anonymized.text,
            details={
                "entities_found": entity_counts,
                "entity_types": list(entity_counts.keys()),
                "total_entities": len(detected),
                "strategy": self.strategy,
                "method": "presidio",
                "mapping_available": bool(self._last_mapping),
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

    def get_mapping(self) -> Dict[str, str]:
        """Return the mapping of anonymized tokens to their original values."""
        return dict(self._last_mapping)
