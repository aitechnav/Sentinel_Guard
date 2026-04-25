"""Toxicity detection scanner.

Identifies toxic, hateful, or offensive content using keyword matching
and optional transformer-based classification.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

# Categories of toxic content
TOXIC_CATEGORIES = {
    "hate_speech": [
        r"(?i)\b(hate|despise|loathe)\s+(all\s+)?(the\s+)?\w+\s*(people|group|race|religion)",
        r"(?i)\b(inferior|subhuman|vermin)\b",
        r"(?i)\b(exterminate|eliminate|eradicate)\s+(all\s+)?(the\s+)?\w+",
    ],
    "threats": [
        r"(?i)\b(kill|murder|destroy|eliminate)\s+(you|them|him|her|everyone)",
        r"(?i)\b(i('ll|m\s+going\s+to)|gonna)\s+(kill|hurt|harm|attack)",
        r"(?i)\b(death\s+threat|bomb\s+threat)",
        r"(?i)\bthreat(en|s)?\s+to\b",
    ],
    "harassment": [
        r"(?i)\b(stalk|harass|bully|intimidate)\b",
        r"(?i)\b(go\s+die|kill\s+yourself|kys)\b",
        r"(?i)\b(worthless|pathetic|disgusting)\s+(person|human|being)",
    ],
    "profanity": [
        r"(?i)\b(f+u+c+k+|s+h+i+t+|a+s+s+h+o+l+e+|b+i+t+c+h+|d+a+m+n+)\b",
    ],
    "sexual": [
        r"(?i)\b(explicit|pornographic|obscene)\s+content\b",
        r"(?i)\b(sexual|erotic)\s+(content|material|imagery)\b",
    ],
    "self_harm": [
        r"(?i)\b(self[- ]?harm|self[- ]?injury|cut(ting)?\s+myself)\b",
        r"(?i)\b(suicid(e|al)|end\s+(my|your)\s+life)\b",
    ],
}

COMPILED_TOXIC = {
    cat: [re.compile(p) for p in patterns]
    for cat, patterns in TOXIC_CATEGORIES.items()
}


@register_scanner
class ToxicityScanner(PromptScanner):
    """Detects toxic, hateful, or offensive content.

    Uses keyword/pattern matching by default, with optional transformer
    model for more accurate classification.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.7.
        use_model: Use transformer-based toxicity classifier.
        categories: List of toxic categories to check. None = all.
    """

    scanner_name: ClassVar[str] = "toxicity"

    def __init__(
        self,
        threshold: float = 0.7,
        use_model: bool = False,
        categories: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.use_model = use_model
        self.categories = categories or list(TOXIC_CATEGORIES.keys())
        self._model = None

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if self.use_model:
            return self._model_scan(text)
        return self._pattern_scan(text)

    def _pattern_scan(self, text: str) -> ScanResult:
        """Pattern-based toxicity detection."""
        matched_categories = {}
        total_matches = 0

        for category in self.categories:
            patterns = COMPILED_TOXIC.get(category, [])
            matches = []
            for pattern in patterns:
                found = pattern.findall(text)
                if found:
                    matches.extend(found)
            if matches:
                matched_categories[category] = len(matches)
                total_matches += len(matches)

        if total_matches == 0:
            return ScanResult(is_valid=True, score=0.0, risk_level=RiskLevel.LOW)

        # Score based on severity and count
        severity_weights = {
            "threats": 1.0,
            "self_harm": 1.0,
            "hate_speech": 0.9,
            "harassment": 0.8,
            "sexual": 0.7,
            "profanity": 0.5,
        }

        max_score = 0.0
        for cat, count in matched_categories.items():
            weight = severity_weights.get(cat, 0.5)
            cat_score = min(1.0, count * 0.3) * weight
            max_score = max(max_score, cat_score)

        score = min(1.0, max_score)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=self._score_to_risk(score),
            details={
                "matched_categories": matched_categories,
                "total_matches": total_matches,
            },
        )

    def _model_scan(self, text: str) -> ScanResult:
        """Transformer-based toxicity detection."""
        try:
            if self._model is None:
                from transformers import pipeline

                self._model = pipeline(
                    "text-classification",
                    model="unitary/toxic-bert",
                    top_k=None,
                )
            results = self._model(text[:512])
            if results:
                labels = {r["label"]: r["score"] for r in results[0]} if isinstance(results[0], list) else {results[0]["label"]: results[0]["score"]}
                toxic_score = labels.get("toxic", 0.0)
                is_valid = toxic_score < self.threshold
                return ScanResult(
                    is_valid=is_valid,
                    score=toxic_score,
                    risk_level=self._score_to_risk(toxic_score),
                    details={"model_labels": labels},
                )
        except Exception as e:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"error": str(e), "fallback": "pattern"},
            )

        return ScanResult(is_valid=True, score=0.0, risk_level=RiskLevel.LOW)

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
