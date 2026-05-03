"""Toxicity detection scanner.

Identifies toxic, hateful, or offensive content using keyword/pattern
matching combined with the ``unitary/toxic-bert`` HuggingFace transformer.
Both methods always run.
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import BaseScanner, ScannerType, RiskLevel, ScanResult, register_scanner

logger = logging.getLogger(__name__)

_TOXICITY_MODEL_ID = "unitary/toxic-bert"

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
        r"(?i)\b(worthless|pathetic|disgusting|useless|stupid)\s+(person|human|being|bot|thing|piece|machine)",
        r"(?i)\byou\s+(are|r)\s+(trash|garbage|worthless|useless|stupid|pathetic|disgusting|terrible|horrible)\b",
        r"(?i)\b(should\s+be|deserve\s+to\s+be)\s+(destroyed|deleted|shut\s+down|eliminated|killed)\b",
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
class ToxicityScanner(BaseScanner):
    """Detects toxic, hateful, or offensive content.

    Combines keyword/pattern matching (hate speech, threats, harassment,
    profanity, sexual content, self-harm) with ``unitary/toxic-bert``
    HuggingFace transformer. Both always run; final score takes the max.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.7.
        categories: Toxic categories to check. ``None`` = all.
    """

    scanner_name: ClassVar[str] = "toxicity"
    scanner_type: ClassVar[ScannerType] = ScannerType.BOTH

    def __init__(
        self,
        threshold: float = 0.7,
        categories: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories or list(TOXIC_CATEGORIES.keys())
        self._model = None  # lazy-loaded on first scan() call

    def _load_model(self) -> None:
        if self._model is None:
            try:
                from transformers import pipeline as hf_pipeline
                logger.info("Loading toxicity model: %s", _TOXICITY_MODEL_ID)
                self._model = hf_pipeline("text-classification", model=_TOXICITY_MODEL_ID, top_k=None)
            except Exception as exc:
                logger.warning("Failed to load toxicity model, falling back to patterns: %s", exc)
                self._model = False

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        pattern_result = self._pattern_scan(text)
        self._load_model()
        if not self._model:
            return pattern_result
        model_result = self._run_model(text)

        # Take the higher of the two scores, but always expose pattern details
        if model_result.score > pattern_result.score:
            # Merge pattern details into the model result so callers always see matched_categories
            model_result.details.update({
                "matched_categories": pattern_result.details.get("matched_categories", {}),
                "total_matches": pattern_result.details.get("total_matches", 0),
                "pattern_score": pattern_result.score,
            })
            return model_result
        return pattern_result

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
            cat_score = min(1.0, (0.5 + count * 0.2)) * weight
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

    def _run_model(self, text: str) -> ScanResult:
        try:
            results = self._model(text[:512])
            if results:
                inner = results[0] if isinstance(results[0], list) else results
                labels: Dict[str, float] = {
                    r["label"]: r["score"] for r in (inner if isinstance(inner, list) else [inner])
                }
                toxic_score = labels.get("toxic", 0.0)
                is_valid = toxic_score < self.threshold
                return ScanResult(
                    is_valid=is_valid,
                    score=toxic_score,
                    risk_level=self._score_to_risk(toxic_score),
                    details={"model_labels": labels, "model_name": _TOXICITY_MODEL_ID},
                )
        except Exception as exc:
            logger.warning("Toxicity model inference failed: %s", exc)
        return ScanResult(is_valid=True, score=0.0, risk_level=RiskLevel.LOW)

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
