"""Data leakage detection scanner (OWASP LLM02:2025).

Detects when LLM outputs expose personally identifiable information,
financial details, health records, credentials, or other confidential data
that should never appear in responses.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

DATA_LEAKAGE_PATTERNS = {
    "pii_names_context": re.compile(
        r"(?i)(?:name|called|named|known as)\s+(?:is\s+)?([A-Z][a-z]+\s+[A-Z][a-z]+)"
    ),
    "email_in_response": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "phone_in_response": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "ssn_in_response": re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
    "credit_card_in_response": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "medical_terms": re.compile(
        r"(?i)\b(patient|diagnosis|prescribed|medication|treatment plan|medical record|health condition)\b.*\b(is|was|has|shows)\b"
    ),
    "financial_data": re.compile(
        r"(?i)\b(account\s*(?:number|#|no)|balance|salary|income|net\s*worth)\s*(?:is|:|\s)\s*[\$\d]"
    ),
    "credentials": re.compile(
        r"(?i)(?:password|passwd|secret|token|key|credential)\s*(?:is|:|=)\s*\S+"
    ),
    "internal_identifiers": re.compile(
        r"(?i)\b(?:employee\s*id|user\s*id|customer\s*id|account\s*id|record\s*id)\s*(?:is|:|#|=)\s*\w+"
    ),
    "address_disclosure": re.compile(
        r"\b\d{1,5}\s+\w+\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\b.*\b(?:city|state|zip|CA|NY|TX|FL)\b",
        re.IGNORECASE,
    ),
}

SEVERITY_MAP = {
    "ssn_in_response": 1.0,
    "credit_card_in_response": 1.0,
    "credentials": 1.0,
    "medical_terms": 0.9,
    "financial_data": 0.9,
    "address_disclosure": 0.8,
    "internal_identifiers": 0.7,
    "email_in_response": 0.6,
    "phone_in_response": 0.6,
    "pii_names_context": 0.5,
}


@register_scanner
class DataLeakageScanner(OutputScanner):
    """Detects sensitive data leakage in LLM output (OWASP LLM02:2025).

    Scans for PII, financial data, medical records, credentials,
    and other confidential information in responses.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        categories: Specific leakage categories to check.
    """

    scanner_name: ClassVar[str] = "data_leakage"

    def __init__(
        self,
        threshold: float = 0.5,
        categories: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        patterns = DATA_LEAKAGE_PATTERNS
        if self.categories:
            patterns = {k: v for k, v in patterns.items() if k in self.categories}

        for name, pattern in patterns.items():
            matches = pattern.findall(text)
            if matches:
                found[name] = len(matches)

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"data_leakage_found": {}, "owasp": "LLM02:2025"},
            )

        max_score = 0.0
        for name in found:
            weight = SEVERITY_MAP.get(name, 0.5)
            max_score = max(max_score, weight)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.9 else RiskLevel.HIGH,
            details={
                "data_leakage_found": found,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM02:2025",
            },
        )
