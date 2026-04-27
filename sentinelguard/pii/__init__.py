"""PII (Personally Identifiable Information) detection and anonymization module.

Provides enterprise-grade PII detection using Presidio with 50+ entity types,
and multiple anonymization strategies.

Usage:
    from sentinelguard.pii import PIIDetector, PIIAnonymizer

    detector = PIIDetector(
        language="en",
        entities=["EMAIL", "PHONE", "CREDIT_CARD", "SSN"],
        score_threshold=0.5
    )
    entities = detector.detect(text)

    anonymizer = PIIAnonymizer(default_strategy="replace")
    anonymized = anonymizer.anonymize(text, entities)
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Built-in entity patterns for fallback
BUILTIN_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "US_SSN": re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "IBAN_CODE": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "US_PASSPORT": re.compile(r"\b[A-Z]\d{8}\b"),
    "US_DRIVER_LICENSE": re.compile(r"\b[A-Z]\d{7,14}\b"),
    "DATE_TIME": re.compile(
        r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
    ),
    "PERSON": re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b"),
    "LOCATION": re.compile(
        r"\b\d{1,5}\s+\w+\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln)\b",
        re.IGNORECASE,
    ),
    "URL": re.compile(r"https?://[^\s]+"),
    "MEDICAL_LICENSE": re.compile(r"\b[A-Z]{2}\d{6,8}\b"),
    "CRYPTO": re.compile(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "US_BANK_NUMBER": re.compile(r"\b\d{8,17}\b"),
}


@dataclass
class PIIEntity:
    """Represents a detected PII entity.

    Attributes:
        entity_type: Type of PII (e.g., EMAIL_ADDRESS, PHONE_NUMBER).
        start: Start position in text.
        end: End position in text.
        score: Confidence score (0.0-1.0).
        text: The actual matched text.
    """

    entity_type: str
    start: int
    end: int
    score: float
    text: str


@dataclass
class AnonymizedResult:
    """Result of anonymization.

    Attributes:
        text: The anonymized text.
        items: List of anonymization operations performed.
        mapping: Mapping from anonymous tokens to original values.
    """

    text: str
    items: List[Dict[str, Any]] = field(default_factory=list)
    mapping: Dict[str, str] = field(default_factory=dict)


class PIIDetector:
    """Enterprise-grade PII detection.

    Uses Presidio when available (50+ entity types), falling back to
    built-in regex patterns.

    Args:
        language: Detection language. Default "en".
        entities: List of entity types to detect. None = all available.
        score_threshold: Minimum confidence score. Default 0.5.
        use_presidio: Try to use Presidio if available. Default True.
    """

    # Full list of Presidio-supported entity types
    PRESIDIO_ENTITIES = [
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
        use_presidio: bool = True,
    ):
        self.language = language
        self.entities = entities
        self.score_threshold = score_threshold
        self._use_presidio = use_presidio
        self._analyzer = None
        self._presidio_available = None

    def _init_presidio(self) -> bool:
        """Initialize Presidio analyzer."""
        if self._presidio_available is not None:
            return self._presidio_available
        try:
            from presidio_analyzer import AnalyzerEngine
            self._analyzer = AnalyzerEngine()
            self._presidio_available = True
            logger.info("Presidio analyzer initialized successfully")
        except ImportError:
            self._presidio_available = False
            logger.info("Presidio not available, using built-in patterns")
        return self._presidio_available

    def detect(self, text: str) -> List[PIIEntity]:
        """Detect PII entities in text.

        Args:
            text: The text to analyze.

        Returns:
            List of detected PIIEntity objects.
        """
        if self._use_presidio and self._init_presidio():
            return self._detect_presidio(text)
        return self._detect_builtin(text)

    def _detect_presidio(self, text: str) -> List[PIIEntity]:
        """Detect using Presidio."""
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
            for r in results
        ]

    def _detect_builtin(self, text: str) -> List[PIIEntity]:
        """Detect using built-in regex patterns."""
        entities = []

        patterns = BUILTIN_PATTERNS
        if self.entities:
            patterns = {
                k: v for k, v in BUILTIN_PATTERNS.items()
                if k in self.entities
            }

        for entity_type, pattern in patterns.items():
            for match in pattern.finditer(text):
                entity = PIIEntity(
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    score=0.85,  # Fixed confidence for regex matches
                    text=match.group(),
                )
                if entity.score >= self.score_threshold:
                    entities.append(entity)

        # Sort by position
        entities.sort(key=lambda e: e.start)
        return entities

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
        - replace: Replace with entity type tag (e.g., <EMAIL_ADDRESS>)
        - mask: Replace with asterisks
        - redact: Remove entirely
        - hash: Replace with hash value
        - fake: Replace with fake data (requires faker)

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

    def anonymize(
        self,
        text: str,
        entities: List[PIIEntity],
    ) -> AnonymizedResult:
        """Anonymize detected PII entities in text.

        Args:
            text: The original text.
            entities: List of detected PIIEntity objects.

        Returns:
            AnonymizedResult with anonymized text and mapping.
        """
        if not entities:
            return AnonymizedResult(text=text)

        # Sort by position (reverse for replacement)
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        result_text = text
        items = []
        mapping = {}

        for entity in sorted_entities:
            strategy = self.entity_strategies.get(
                entity.entity_type, self.default_strategy
            )
            replacement = self._apply_strategy(entity, strategy)
            mapping[replacement] = entity.text

            result_text = (
                result_text[:entity.start]
                + replacement
                + result_text[entity.end:]
            )

            items.append({
                "entity_type": entity.entity_type,
                "original_start": entity.start,
                "original_end": entity.end,
                "strategy": strategy,
                "replacement": replacement,
            })

        items.reverse()  # Restore original order

        return AnonymizedResult(
            text=result_text,
            items=items,
            mapping=mapping,
        )

    def _apply_strategy(self, entity: PIIEntity, strategy: str) -> str:
        """Apply anonymization strategy to an entity."""
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
        else:
            return f"<{entity.entity_type}>"

    def _generate_fake(self, entity_type: str) -> str:
        """Generate fake data for an entity type."""
        try:
            if self._faker is None:
                from faker import Faker
                self._faker = Faker()

            fake_generators = {
                "EMAIL_ADDRESS": self._faker.email,
                "PHONE_NUMBER": self._faker.phone_number,
                "PERSON": self._faker.name,
                "LOCATION": self._faker.address,
                "CREDIT_CARD": self._faker.credit_card_number,
                "DATE_TIME": lambda: self._faker.date(),
                "URL": self._faker.url,
                "IP_ADDRESS": self._faker.ipv4,
            }

            generator = fake_generators.get(entity_type)
            if generator:
                return generator()
        except ImportError:
            pass

        return f"<{entity_type}>"


__all__ = [
    "PIIDetector",
    "PIIAnonymizer",
    "PIIEntity",
    "AnonymizedResult",
]
