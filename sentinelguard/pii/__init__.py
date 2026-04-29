"""PII (Personally Identifiable Information) detection and anonymization module.

Provides enterprise-grade PII detection using Microsoft Presidio (mandatory
dependency) with 30+ entity types, and multiple anonymization strategies.

Usage:
    from sentinelguard.pii import PIIDetector, PIIAnonymizer

    detector = PIIDetector(
        language="en",
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN"],
    )
    entities = detector.detect(text)

    anonymizer = PIIAnonymizer(default_strategy="replace")
    anonymized = anonymizer.anonymize(text, entities)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from presidio_analyzer import AnalyzerEngine

logger = logging.getLogger(__name__)


@dataclass
class PIIEntity:
    """Represents a detected PII entity."""

    entity_type: str
    start: int
    end: int
    score: float
    text: str


@dataclass
class AnonymizedResult:
    """Result of anonymization."""

    text: str
    items: List[Dict[str, Any]] = field(default_factory=list)
    mapping: Dict[str, str] = field(default_factory=dict)


class PIIDetector:
    """Enterprise-grade PII detection powered by Microsoft Presidio.

    Detects 30+ entity types: EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD,
    US_SSN, IBAN_CODE, US_PASSPORT, IP_ADDRESS, PERSON, LOCATION,
    CRYPTO, MEDICAL_LICENSE, US_DRIVER_LICENSE, and more.

    Args:
        language: Detection language. Default "en".
        entities: List of entity types to detect. ``None`` = all supported.
        score_threshold: Minimum confidence score (0.0–1.0). Default 0.5.
    """

    SUPPORTED_ENTITIES = [
        "CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS",
        "IBAN_CODE", "IP_ADDRESS", "NRP", "LOCATION", "PERSON",
        "PHONE_NUMBER", "MEDICAL_LICENSE", "URL",
        "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_ITIN",
        "US_PASSPORT", "US_SSN", "UK_NHS", "ES_NIF", "IT_FISCAL_CODE",
        "IT_DRIVER_LICENSE", "IT_VAT_CODE", "IT_PASSPORT",
        "IT_IDENTITY_CARD", "SG_NRIC_FIN", "AU_ABN", "AU_ACN",
        "AU_TFN", "AU_MEDICARE", "IN_PAN", "IN_AADHAAR",
        "IN_VEHICLE_REGISTRATION",
    ]

    SUPPORTED_LANGUAGES = ["en", "es", "fr", "de", "it", "pt", "nl", "he"]

    def __init__(
        self,
        language: str = "en",
        entities: Optional[List[str]] = None,
        score_threshold: float = 0.5,
    ):
        self.language = language
        self.entities = entities
        self.score_threshold = score_threshold
        self._analyzer = AnalyzerEngine()
        logger.info("Presidio AnalyzerEngine initialized")

    def detect(self, text: str) -> List[PIIEntity]:
        """Detect PII entities in text using Presidio.

        Args:
            text: The text to analyze.

        Returns:
            List of detected PIIEntity objects sorted by position.
        """
        results = self._analyzer.analyze(
            text=text,
            entities=self.entities,
            language=self.language,
            score_threshold=self.score_threshold,
        )
        return [
            PIIEntity(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=r.score,
                text=text[r.start:r.end],
            )
            for r in sorted(results, key=lambda r: r.start)
        ]

    def detect_batch(self, texts: List[str]) -> List[List[PIIEntity]]:
        """Detect PII in multiple texts.

        Args:
            texts: List of texts to analyze.

        Returns:
            List of entity lists, one per input text.
        """
        return [self.detect(text) for text in texts]


class PIIAnonymizer:
    """PII anonymization with multiple strategies.

    Strategies:
        - replace: Replace with entity type tag (e.g. ``<EMAIL_ADDRESS>``)
        - mask:    Replace with asterisks
        - redact:  Remove entirely
        - hash:    Replace with SHA-256 hash (12 chars)
        - fake:    Replace with synthetic data (requires ``faker``)

    Args:
        default_strategy: Default anonymization strategy. Default "replace".
        entity_strategies: Dict mapping entity types to specific strategies.
    """

    def __init__(
        self,
        default_strategy: str = "replace",
        entity_strategies: Optional[Dict[str, str]] = None,
    ):
        self.default_strategy = default_strategy
        self.entity_strategies = entity_strategies or {}
        self._faker = None

    def anonymize(self, text: str, entities: List[PIIEntity]) -> AnonymizedResult:
        """Anonymize detected PII entities in text.

        Args:
            text: The original text.
            entities: List of detected PIIEntity objects.

        Returns:
            AnonymizedResult with anonymized text and mapping.
        """
        if not entities:
            return AnonymizedResult(text=text)

        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        result_text = text
        items = []
        mapping = {}

        for entity in sorted_entities:
            strategy = self.entity_strategies.get(entity.entity_type, self.default_strategy)
            replacement = self._apply_strategy(entity, strategy)
            mapping[replacement] = entity.text
            result_text = result_text[:entity.start] + replacement + result_text[entity.end:]
            items.append({
                "entity_type": entity.entity_type,
                "original_start": entity.start,
                "original_end": entity.end,
                "strategy": strategy,
                "replacement": replacement,
            })

        items.reverse()
        return AnonymizedResult(text=result_text, items=items, mapping=mapping)

    def _apply_strategy(self, entity: PIIEntity, strategy: str) -> str:
        if strategy == "replace":
            return f"<{entity.entity_type}>"
        elif strategy == "mask":
            return "*" * len(entity.text)
        elif strategy == "redact":
            return ""
        elif strategy == "hash":
            return hashlib.sha256(entity.text.encode()).hexdigest()[:12]
        elif strategy == "fake":
            return self._generate_fake(entity.entity_type)
        return f"<{entity.entity_type}>"

    def _generate_fake(self, entity_type: str) -> str:
        try:
            if self._faker is None:
                from faker import Faker
                self._faker = Faker()
            generators = {
                "EMAIL_ADDRESS": self._faker.email,
                "PHONE_NUMBER": self._faker.phone_number,
                "PERSON": self._faker.name,
                "LOCATION": self._faker.address,
                "CREDIT_CARD": self._faker.credit_card_number,
                "DATE_TIME": lambda: self._faker.date(),
                "URL": self._faker.url,
                "IP_ADDRESS": self._faker.ipv4,
            }
            gen = generators.get(entity_type)
            if gen:
                return gen()
        except ImportError:
            pass
        return f"<{entity_type}>"


__all__ = ["PIIDetector", "PIIAnonymizer", "PIIEntity", "AnonymizedResult"]
