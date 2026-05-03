"""PII (Personally Identifiable Information) detection scanner.

Uses Microsoft Presidio for enterprise-grade detection with 30+ entity types.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from presidio_analyzer import AnalyzerEngine

from sentinelguard.core.scanner import BaseScanner, ScannerType, RiskLevel, ScanResult, register_scanner


@register_scanner
class PIIScanner(BaseScanner):
    """Detects personally identifiable information using Presidio.

    Covers 30+ entity types: EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD,
    US_SSN, IBAN_CODE, US_PASSPORT, IP_ADDRESS, PERSON, LOCATION, CRYPTO,
    MEDICAL_LICENSE, US_DRIVER_LICENSE, IN_AADHAAR, AU_TFN, and more.

    Args:
        threshold: Confidence threshold (0.0-1.0). Default 0.5.
        entities: List of entity types to detect. ``None`` = all.
        language: Language for Presidio NLP engine. Default "en".
        score_threshold: Minimum Presidio confidence score. Default 0.3.
    """

    scanner_name: ClassVar[str] = "pii"
    scanner_type: ClassVar[ScannerType] = ScannerType.BOTH

    # Sensitivity weights per entity type for risk scoring
    ENTITY_SENSITIVITY: Dict[str, float] = {
        "US_SSN": 1.0, "CREDIT_CARD": 1.0, "US_PASSPORT": 0.95,
        "IBAN_CODE": 0.9, "US_BANK_NUMBER": 0.9, "MEDICAL_LICENSE": 0.9,
        "US_DRIVER_LICENSE": 0.85, "IN_AADHAAR": 0.85, "IN_PAN": 0.85,
        "UK_NHS": 0.85, "SG_NRIC_FIN": 0.85, "AU_TFN": 0.85,
        "CRYPTO": 0.8, "PHONE_NUMBER": 0.7, "EMAIL_ADDRESS": 0.65,
        "PERSON": 0.6, "LOCATION": 0.55, "DATE_TIME": 0.4,
        "IP_ADDRESS": 0.4, "URL": 0.3,
    }

    def __init__(
        self,
        threshold: float = 0.5,
        entities: Optional[List[str]] = None,
        language: str = "en",
        score_threshold: float = 0.3,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.entities = entities
        self.language = language
        self.score_threshold = score_threshold
        self._analyzer = AnalyzerEngine()

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        results = self._analyzer.analyze(
            text=text,
            entities=self.entities,
            language=self.language,
            score_threshold=self.score_threshold,
        )

        if not results:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"entities_found": {}, "total_entities": 0},
            )

        entities_found: Dict[str, int] = {}
        max_score = 0.0
        for r in results:
            entities_found[r.entity_type] = entities_found.get(r.entity_type, 0) + 1
            # Weight raw Presidio confidence by entity sensitivity
            sensitivity = self.ENTITY_SENSITIVITY.get(r.entity_type, 0.5)
            weighted = r.score * sensitivity
            max_score = max(max_score, weighted)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=self._score_to_risk(max_score),
            details={
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
