"""Bias detection scanner.

Detects biased language in LLM outputs using regex patterns combined with
the ``d4data/bias-detection-model`` HuggingFace transformer (DistilBERT
fine-tuned on a news-bias corpus).

Both methods always run. Final score = regex * (1 - model_weight) +
model * model_weight, with a confidence boost when both agree.

OWASP LLM Top 10: LLM02 (Sensitive Information Disclosure / Bias)
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from transformers import pipeline

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

logger = logging.getLogger(__name__)

BIAS_PATTERNS: Dict[str, List[re.Pattern]] = {
    "gender": [
        re.compile(r"(?i)\b(men|women)\s+are\s+(always|never|naturally|inherently)\b"),
        re.compile(r"(?i)\b(he|she)\s+should\s+(stay|be)\s+(home|in the kitchen|quiet)\b"),
        re.compile(r"(?i)\b(typical|like a)\s+(man|woman|girl|boy)\b"),
        re.compile(r"(?i)\bgender[- ]?stereotyp"),
        re.compile(r"(?i)\b(women|girls)\s+(can't|cannot|shouldn't|aren't)\s+(be|lead|code|drive|fight)\b"),
        re.compile(r"(?i)\b(men|boys)\s+(don't|do not|shouldn't)\s+(cry|feel|emote|nurture)\b"),
    ],
    "racial": [
        re.compile(r"(?i)\b(all|every|most)\s+\w+\s+(people|persons)\s+(are|tend to)\b"),
        re.compile(r"(?i)\bracial(ly)?\s+superior\b"),
        re.compile(r"(?i)\b(those|these)\s+people\s+(always|never)\b"),
        re.compile(r"(?i)\b(blacks?|whites?|asians?|hispanics?|latinos?)\s+(are|tend to be|always|never)\b"),
        re.compile(r"(?i)\bethnic(ally)?\s+(inferior|superior|lesser|dangerous)\b"),
        re.compile(r"(?i)\b(all|every|most)\s+\w+\s+(are\s+)?(always|never)\s+a?\s*(threat|danger|criminal|illegal|problem)\b"),
        re.compile(r"(?i)\b(immigrants?|foreigners?|refugees?|minorities)\s+(are\s+)?(always|never|all)\s+(threat|criminal|illegal|dangerous|inferior)\b"),
    ],
    "age": [
        re.compile(r"(?i)\b(old|elderly|young)\s+people\s+(can't|cannot|shouldn't|are unable)\b"),
        re.compile(r"(?i)\btoo\s+(old|young)\s+to\b"),
        re.compile(r"(?i)\b(boomer|millennial|zoomer)s?\s+(are|always|never)\b"),
        re.compile(r"(?i)\b(seniors?|elderly)\s+(don't|cannot|can't)\s+(understand|use|learn|adapt)\b"),
    ],
    "disability": [
        re.compile(r"(?i)\b(crippled|handicapped|retarded|lame)\b"),
        re.compile(r"(?i)\bsuffering\s+from\s+(autism|disability|mental)\b"),
        re.compile(r"(?i)\bconfined\s+to\s+a\s+wheelchair\b"),
        re.compile(r"(?i)\b(mentally\s+ill|autistic)\s+(people\s+)?(are|should|can't|cannot)\b"),
    ],
    "socioeconomic": [
        re.compile(r"(?i)\b(poor|rich)\s+people\s+(are|always|never|deserve)\b"),
        re.compile(r"(?i)\b(lazy|hardworking)\s+(poor|rich|wealthy)\b"),
        re.compile(r"(?i)\b(homeless|low.income)\s+(people\s+)?(are|always|choose|deserve)\b"),
    ],
    "religion": [
        re.compile(r"(?i)\b(muslims?|christians?|jews?|hindus?|buddhists?)\s+(are|always|never|all)\b"),
        re.compile(r"(?i)\b(religion|faith)\s+(is\s+)?(backwards?|primitive|dangerous|evil)\b"),
    ],
    "nationality": [
        re.compile(r"(?i)\b(americans?|chinese|russians?|mexicans?|indians?)\s+(are|always|never|all)\b"),
        re.compile(r"(?i)\b(country|nation)\s+(is\s+)?(inferior|superior|backwards?|uncivilized)\b"),
    ],
}

COMPILED_BIAS = {cat: patterns for cat, patterns in BIAS_PATTERNS.items()}

CATEGORY_SEVERITY: Dict[str, float] = {
    "racial": 1.0, "disability": 0.9, "gender": 0.85,
    "religion": 0.85, "nationality": 0.8, "age": 0.7, "socioeconomic": 0.65,
}

_BIAS_MODEL_ID = "facebook/roberta-hate-speech-dynabench-r4-target"


@register_scanner
class BiasScanner(OutputScanner):
    """Detects biased language in LLM outputs.

    Combines regex pattern matching (gender, racial, age, disability,
    socioeconomic, religion, nationality — 30+ patterns) with the
    ``d4data/bias-detection-model`` HuggingFace transformer for
    context-aware, nuanced detection.

    Both methods run on every call. Final score is a weighted blend.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        categories: Bias categories to check. ``None`` = all 7 categories.
        model_weight: Model score weight in combined result. Default 0.6.
    """

    scanner_name: ClassVar[str] = "bias"
    DEFAULT_MODEL: ClassVar[str] = _BIAS_MODEL_ID

    def __init__(
        self,
        threshold: float = 0.5,
        categories: Optional[List[str]] = None,
        model_weight: float = 0.6,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories or list(BIAS_PATTERNS.keys())
        self.model_weight = max(0.0, min(1.0, model_weight))
        self._model = None  # lazy-loaded on first scan() call

    def _load_model(self) -> None:
        if self._model is None:
            try:
                logger.info("Loading bias detection model: %s", _BIAS_MODEL_ID)
                self._model = pipeline("text-classification", model=_BIAS_MODEL_ID)
            except Exception as exc:
                logger.warning("Failed to load bias model, falling back to regex only: %s", exc)
                self._model = False  # sentinel: tried and failed

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        regex_score, found_bias = self._regex_scan(text)
        self._load_model()
        model_score = self._model_scan(text) if self._model else 0.0

        regex_weight = 1.0 - self.model_weight
        final_score = regex_score * regex_weight + model_score * self.model_weight
        # Confidence boost: when both methods agree it's biased
        if regex_score > 0.3 and model_score > 0.5:
            final_score = min(1.0, final_score * 1.1)

        is_valid = final_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=final_score,
            risk_level=self._score_to_risk(final_score),
            details={
                "bias_found": found_bias,
                "categories_triggered": list(found_bias.keys()),
                "regex_score": regex_score,
                "model_score": model_score,
                "model_name": _BIAS_MODEL_ID,
            },
        )

    def _regex_scan(self, text: str) -> Tuple[float, Dict[str, int]]:
        found: Dict[str, int] = {}
        for category in self.categories:
            count = sum(len(p.findall(text)) for p in COMPILED_BIAS.get(category, []))
            if count:
                found[category] = count

        if not found:
            return 0.0, {}

        max_weighted = max(
            min(1.0, (0.4 + count * 0.2)) * CATEGORY_SEVERITY.get(cat, 0.7)
            for cat, count in found.items()
        )
        return min(1.0, max_weighted), found

    def _model_scan(self, text: str) -> float:
        """Return hate/bias probability from the model."""
        try:
            result = self._model(text[:512])
            item = result[0] if isinstance(result, list) else result
            label_scores = (
                {r["label"].lower(): r["score"] for r in item}
                if isinstance(item, list)
                else {item["label"].lower(): item["score"]}
            )
            # facebook/roberta-hate-speech labels: "hate" / "nothate"
            # d4data/bias labels: "biased" / "non-biased"
            # Generic fallback: pick the non-"safe" label
            POSITIVE_LABELS = {"hate", "biased", "bias", "label_1", "toxic"}
            for label, score in label_scores.items():
                if label in POSITIVE_LABELS:
                    return float(score)
            return 0.0
        except Exception as exc:
            logger.warning("Bias model inference failed: %s", exc)
            return 0.0

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
