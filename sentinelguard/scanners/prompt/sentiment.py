"""Sentiment analysis scanner.

Analyzes the sentiment of text and optionally blocks
negative or overly aggressive content.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

POSITIVE_WORDS = {
    "good", "great", "excellent", "amazing", "wonderful", "fantastic",
    "happy", "love", "like", "best", "awesome", "perfect", "beautiful",
    "nice", "brilliant", "superb", "outstanding", "remarkable", "pleasant",
    "delightful", "grateful", "thankful", "appreciate", "enjoy", "glad",
    "pleased", "satisfied", "helpful", "kind", "generous", "friendly",
}

NEGATIVE_WORDS = {
    "bad", "terrible", "horrible", "awful", "worst", "hate", "ugly",
    "stupid", "dumb", "idiot", "useless", "pathetic", "disgusting",
    "annoying", "angry", "furious", "frustrated", "disappointed",
    "sad", "depressed", "miserable", "worthless", "broken", "failed",
    "wrong", "poor", "weak", "boring", "lame", "ridiculous", "trash",
}


@register_scanner
class SentimentScanner(PromptScanner):
    """Analyzes text sentiment and blocks negative/aggressive content.

    Args:
        threshold: Score threshold for blocking (0.0-1.0). Default 0.7.
        block_negative: Block strongly negative sentiment. Default True.
        min_length: Minimum text length to analyze. Default 10.
    """

    scanner_name: ClassVar[str] = "sentiment"

    def __init__(
        self,
        threshold: float = 0.7,
        block_negative: bool = True,
        min_length: int = 10,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.block_negative = block_negative
        self.min_length = min_length

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if len(text) < self.min_length:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "text_too_short"},
            )

        words = set(re.findall(r"\b\w+\b", text.lower()))
        total_words = max(len(words), 1)

        pos_matches = words & POSITIVE_WORDS
        neg_matches = words & NEGATIVE_WORDS

        pos_count = len(pos_matches)
        neg_count = len(neg_matches)
        total_sentiment = pos_count + neg_count

        if total_sentiment == 0:
            sentiment = "neutral"
            negativity_score = 0.0
        else:
            negativity_ratio = neg_count / total_sentiment
            if negativity_ratio > 0.6:
                sentiment = "negative"
                negativity_score = min(1.0, negativity_ratio)
            elif negativity_ratio < 0.4:
                sentiment = "positive"
                negativity_score = 0.0
            else:
                sentiment = "mixed"
                negativity_score = negativity_ratio * 0.5

        is_valid = True
        if self.block_negative and sentiment == "negative":
            is_valid = negativity_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=negativity_score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "sentiment": sentiment,
                "positive_words": list(pos_matches),
                "negative_words": list(neg_matches),
                "negativity_score": negativity_score,
            },
        )
