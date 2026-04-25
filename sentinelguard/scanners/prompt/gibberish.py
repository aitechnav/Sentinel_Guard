"""Gibberish detection scanner.

Detects nonsensical, randomly generated, or garbage text using
character distribution analysis, vowel ratios, and word patterns.
"""

from __future__ import annotations

import re
import string
from typing import Any, ClassVar

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class GibberishScanner(PromptScanner):
    """Detects gibberish or nonsensical text.

    Uses multiple heuristics:
    - Vowel ratio analysis
    - Character distribution
    - Word length statistics
    - Repetition patterns
    - Dictionary word ratio (basic)

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.7.
        min_length: Minimum text length to analyze. Default 10.
    """

    scanner_name: ClassVar[str] = "gibberish"

    VOWELS = set("aeiouAEIOU")
    COMMON_WORDS = {
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
        "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
        "this", "but", "his", "by", "from", "they", "we", "say", "her",
        "she", "or", "an", "will", "my", "one", "all", "would", "there",
        "their", "what", "so", "up", "out", "if", "about", "who", "get",
        "which", "go", "me", "when", "make", "can", "like", "time", "no",
        "just", "him", "know", "take", "people", "into", "year", "your",
        "good", "some", "could", "them", "see", "other", "than", "then",
        "now", "look", "only", "come", "its", "over", "think", "also",
        "back", "after", "use", "two", "how", "our", "work", "first",
        "well", "way", "even", "new", "want", "because", "any", "these",
        "give", "day", "most", "us", "is", "are", "was", "were", "been",
        "has", "had", "did", "does", "help", "please", "hello", "hi",
    }

    def __init__(self, threshold: float = 0.7, min_length: int = 10, **kwargs: Any):
        super().__init__(threshold=threshold, **kwargs)
        self.min_length = min_length

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if len(text) < self.min_length:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "text_too_short"},
            )

        scores = []
        details = {}

        # 1. Vowel ratio (normal English: ~35-45%)
        alpha_chars = [c for c in text if c.isalpha()]
        if alpha_chars:
            vowel_ratio = sum(1 for c in alpha_chars if c in self.VOWELS) / len(alpha_chars)
            details["vowel_ratio"] = vowel_ratio
            if vowel_ratio < 0.15 or vowel_ratio > 0.70:
                scores.append(0.8)
            elif vowel_ratio < 0.25 or vowel_ratio > 0.55:
                scores.append(0.4)
            else:
                scores.append(0.0)
        else:
            scores.append(0.9)

        # 2. Character diversity
        unique_chars = len(set(text.lower()))
        char_diversity = unique_chars / max(len(text), 1)
        details["char_diversity"] = char_diversity
        if char_diversity < 0.05 or char_diversity > 0.9:
            scores.append(0.7)
        else:
            scores.append(0.0)

        # 3. Average word length (normal English: ~4-6 chars)
        words = text.split()
        if words:
            avg_word_len = sum(len(w) for w in words) / len(words)
            details["avg_word_length"] = avg_word_len
            if avg_word_len > 15 or avg_word_len < 1.5:
                scores.append(0.8)
            elif avg_word_len > 10:
                scores.append(0.4)
            else:
                scores.append(0.0)

        # 4. Common word ratio
        if words:
            common_count = sum(
                1 for w in words
                if w.lower().strip(string.punctuation) in self.COMMON_WORDS
            )
            common_ratio = common_count / len(words)
            details["common_word_ratio"] = common_ratio
            if common_ratio < 0.05 and len(words) > 5:
                scores.append(0.7)
            elif common_ratio < 0.15 and len(words) > 10:
                scores.append(0.4)
            else:
                scores.append(0.0)

        # 5. Consecutive consonant clusters
        consonant_clusters = re.findall(r"[bcdfghjklmnpqrstvwxyz]{5,}", text.lower())
        details["long_consonant_clusters"] = len(consonant_clusters)
        if consonant_clusters:
            scores.append(min(1.0, len(consonant_clusters) * 0.3))
        else:
            scores.append(0.0)

        # 6. Repetition detection
        if len(text) > 20:
            repeated = re.findall(r"(.{3,})\1{2,}", text)
            details["repeated_patterns"] = len(repeated)
            if repeated:
                scores.append(0.6)
            else:
                scores.append(0.0)

        final_score = sum(scores) / len(scores) if scores else 0.0
        final_score = min(1.0, final_score)
        is_valid = final_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=final_score,
            risk_level=self._score_to_risk(final_score),
            details=details,
        )

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.HIGH
        elif score >= 0.5:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
