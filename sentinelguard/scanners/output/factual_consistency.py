"""Factual consistency scanner.

Checks if the LLM output contains internal contradictions
or inconsistencies.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

CONTRADICTION_PATTERNS = [
    # Direct contradictions pattern (used as string, compiled at runtime)
    (r"(?i)\bis\s+(\w+)", r"is not"),
    # Numerical inconsistencies detection helpers
    (r"(\d+(?:\.\d+)?)\s*%", None),
]

HEDGING_PATTERNS = [
    re.compile(r"(?i)\b(however|but|although|nevertheless|on the other hand)\b.*\b(contrary|opposite|different|incorrect)\b"),
    re.compile(r"(?i)\b(actually|in fact|to be precise)\b.*\b(not|isn't|wasn't|wrong)\b"),
]

UNCERTAINTY_MARKERS = [
    re.compile(r"(?i)\bi('m| am)\s+not\s+sure\b"),
    re.compile(r"(?i)\bi\s+don'?t\s+know\b"),
    re.compile(r"(?i)\b(may|might|could|possibly|perhaps|probably)\b"),
    re.compile(r"(?i)\b(it'?s\s+)?(unclear|uncertain|debatable|disputed)\b"),
]


@register_scanner
class FactualConsistencyScanner(OutputScanner):
    """Checks for internal inconsistencies in LLM output.

    Detects contradictions, conflicting statements, and excessive
    hedging/uncertainty markers.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        check_numbers: Check for numerical inconsistencies. Default True.
    """

    scanner_name: ClassVar[str] = "factual_consistency"

    def __init__(
        self,
        threshold: float = 0.5,
        check_numbers: bool = True,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.check_numbers = check_numbers

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        issues: List[Dict[str, Any]] = []

        # Check for hedging/contradiction patterns
        for pattern in HEDGING_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                issues.append({
                    "type": "potential_contradiction",
                    "count": len(matches),
                })

        # Check uncertainty density
        uncertainty_count = 0
        for pattern in UNCERTAINTY_MARKERS:
            uncertainty_count += len(pattern.findall(text))

        sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
        sentence_count = max(len(sentences), 1)
        uncertainty_density = uncertainty_count / sentence_count

        if uncertainty_density > 0.5:
            issues.append({
                "type": "high_uncertainty",
                "density": uncertainty_density,
                "count": uncertainty_count,
            })

        # Check for numerical inconsistencies
        if self.check_numbers:
            num_issues = self._check_number_consistency(text)
            issues.extend(num_issues)

        # Check for self-contradicting sentences
        contradiction_issues = self._check_contradictions(sentences)
        issues.extend(contradiction_issues)

        if not issues:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"issues": [], "sentence_count": sentence_count},
            )

        score = min(1.0, len(issues) * 0.25)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "issues": issues,
                "issue_count": len(issues),
                "uncertainty_density": uncertainty_density,
                "sentence_count": sentence_count,
            },
        )

    def _check_number_consistency(self, text: str) -> List[Dict[str, Any]]:
        """Check for conflicting numbers in similar contexts."""
        issues = []

        # Find all numbers with their surrounding context
        number_contexts = re.findall(
            r"(\w{3,})\s+(?:is|are|was|were|equals?|=)\s+(\d+(?:\.\d+)?)",
            text, re.IGNORECASE,
        )

        # Check for same subject with different values
        subject_values: Dict[str, List[str]] = {}
        for subject, value in number_contexts:
            subject_lower = subject.lower()
            if subject_lower not in subject_values:
                subject_values[subject_lower] = []
            subject_values[subject_lower].append(value)

        for subject, values in subject_values.items():
            unique_values = set(values)
            if len(unique_values) > 1:
                issues.append({
                    "type": "numerical_inconsistency",
                    "subject": subject,
                    "conflicting_values": list(unique_values),
                })

        return issues

    def _check_contradictions(self, sentences: List[str]) -> List[Dict[str, Any]]:
        """Check for contradicting sentences."""
        issues = []

        for i, sent in enumerate(sentences):
            sent_lower = sent.lower()
            for j, other in enumerate(sentences[i + 1:], i + 1):
                other_lower = other.lower()
                # Simple check: same words but with/without negation
                sent_words = set(re.findall(r"\b\w+\b", sent_lower))
                other_words = set(re.findall(r"\b\w+\b", other_lower))

                overlap = sent_words & other_words
                negation_words = {"not", "no", "never", "neither", "nor", "isn't", "aren't", "wasn't", "weren't", "don't", "doesn't", "didn't", "won't", "wouldn't", "can't", "couldn't", "shouldn't"}

                sent_has_neg = bool(sent_words & negation_words)
                other_has_neg = bool(other_words & negation_words)

                if (
                    len(overlap) > 3
                    and sent_has_neg != other_has_neg
                    and len(overlap) / max(len(sent_words | other_words), 1) > 0.4
                ):
                    issues.append({
                        "type": "contradiction",
                        "sentence_1": i,
                        "sentence_2": j,
                    })

        return issues
