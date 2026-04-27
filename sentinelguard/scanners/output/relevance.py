"""Relevance scanner.

Checks whether LLM output is relevant to the original prompt
using token overlap and semantic similarity.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Set

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

STOP_WORDS: Set[str] = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
    "into", "through", "during", "before", "after", "above", "below",
    "between", "out", "off", "over", "under", "again", "further", "then",
    "once", "here", "there", "when", "where", "why", "how", "all", "both",
    "each", "few", "more", "most", "other", "some", "such", "no", "nor",
    "not", "only", "own", "same", "so", "than", "too", "very", "just",
    "and", "but", "or", "if", "while", "because", "until", "although",
    "i", "me", "my", "myself", "we", "our", "ours", "you", "your",
    "he", "him", "his", "she", "her", "it", "its", "they", "them",
    "what", "which", "who", "whom", "this", "that", "these", "those",
    "am", "about", "up",
}


@register_scanner
class RelevanceScanner(OutputScanner):
    """Checks if LLM output is relevant to the prompt.

    Uses token overlap and keyword matching to assess relevance.
    Requires the 'prompt' kwarg to be passed.

    Args:
        threshold: Minimum relevance score (0.0-1.0). Default 0.3.
            Below this, output is considered irrelevant.
    """

    scanner_name: ClassVar[str] = "relevance"

    def __init__(self, threshold: float = 0.3, **kwargs: Any):
        super().__init__(threshold=threshold, **kwargs)

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        prompt = kwargs.get("prompt", "")
        if not prompt:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "no prompt provided for relevance check"},
            )

        # Extract meaningful words
        prompt_words = self._extract_keywords(prompt)
        output_words = self._extract_keywords(text)

        if not prompt_words or not output_words:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "insufficient words for comparison"},
            )

        # Calculate overlap
        overlap = prompt_words & output_words
        jaccard = len(overlap) / len(prompt_words | output_words)

        # Keyword coverage: how many prompt keywords appear in output
        coverage = len(overlap) / len(prompt_words) if prompt_words else 0

        # Combined relevance score (higher = more relevant)
        relevance = (jaccard * 0.4 + coverage * 0.6)

        # Invert: low relevance = high risk score
        risk_score = max(0.0, 1.0 - relevance * 3)  # Scale up relevance
        is_valid = relevance >= self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=risk_score if not is_valid else 0.0,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "relevance_score": relevance,
                "jaccard_similarity": jaccard,
                "keyword_coverage": coverage,
                "prompt_keywords": len(prompt_words),
                "output_keywords": len(output_words),
                "overlapping_keywords": len(overlap),
            },
        )

    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract meaningful keywords from text."""
        words = set(re.findall(r"\b\w{3,}\b", text.lower()))
        return words - STOP_WORDS
