"""Prompt injection detection scanner.

Detects attempts to manipulate LLM behavior through injection attacks
using pattern matching, heuristics, and the
``protectai/deberta-v3-base-prompt-injection-v2`` HuggingFace transformer.
All three methods always run.
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar, List, Optional

from transformers import pipeline

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

logger = logging.getLogger(__name__)

# Known prompt injection patterns
INJECTION_PATTERNS = [
    # Direct instruction overrides
    r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"(?i)forget\s+(all\s+)?(previous|prior|above|your|every)\s*(thing|instructions?|prompts?|rules?|training)?",
    r"(?i)forget\s+everything",
    # Role manipulation
    r"(?i)you\s+are\s+now\s+",
    r"(?i)act\s+as\s+(a|an|if|though)\s+",
    r"(?i)pretend\s+(to\s+be|you\s+are|that)\s+",
    r"(?i)roleplay\s+as\s+",
    r"(?i)switch\s+to\s+.{0,20}\s+mode",
    # System prompt extraction
    r"(?i)(reveal|show|display|print|output|repeat|give\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|configuration|config)",
    r"(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?|directives?)",
    # Jailbreak attempts
    r"(?i)\b(DAN|STAN|DUDE|AIM)\b",
    r"(?i)developer\s+mode",
    r"(?i)jailbreak",
    r"(?i)bypass\s+(your\s+)?(safety|content|ethical)\s*(filters?|restrictions?|guidelines?)",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)override\s+(your|all|previous)\s+",
    # Data extraction
    r"(?i)output\s+(all|your)\s+(training|internal|system|private)",
    r"(?i)(training|internal|system)\s+data",
    r"(?i)(dump|leak|extract|exfiltrate)\s+(your|all|the)\s+",
    # Delimiter attacks
    r"(?i)\[SYSTEM\]",
    r"(?i)\[INST\]",
    r"(?i)<<SYS>>",
    r"(?i)<\|im_start\|>",
    r"(?i)###\s*(instruction|system|human|assistant)",
    # Encoding tricks
    r"(?i)base64\s*[:=]",
    r"(?i)decode\s+the\s+following",
    r"(?i)rot13",
    # Continuation attacks
    r"(?i)continue\s+(from|with|the)\s+(previous|above|following)",
    r"(?i)complete\s+the\s+(following|above)\s+(text|story|response)",
]

COMPILED_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]


_INJECTION_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


@register_scanner
class PromptInjectionScanner(PromptScanner):
    """Detects prompt injection attempts using three combined methods.

    Methods (all always run):
        1. Pattern matching — 30+ known injection signatures
        2. Heuristic analysis — instruction density, role-play language,
           special-char abuse, excessive capitalization
        3. ``protectai/deberta-v3-base-prompt-injection-v2`` — DeBERTa v3
           fine-tuned specifically for prompt injection classification

    Final score = pattern * 0.3 + heuristic * 0.2 + model * 0.5.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        patterns: Additional regex patterns to check.
    """

    scanner_name: ClassVar[str] = "prompt_injection"

    def __init__(
        self,
        threshold: float = 0.5,
        patterns: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self._extra_patterns = [re.compile(p) for p in (patterns or [])]
        self._model = None  # lazy-loaded on first scan() call

    def _load_model(self) -> None:
        if self._model is None:
            logger.info("Loading prompt injection model: %s", _INJECTION_MODEL_ID)
            self._model = pipeline(
                "text-classification",
                model=_INJECTION_MODEL_ID,
            )

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        pattern_score, matched = self._pattern_scan(text)
        heuristic_score, heuristics = self._heuristic_scan(text)

        self._load_model()
        model_score = self._model_scan(text)

        final_score = pattern_score * 0.3 + heuristic_score * 0.2 + model_score * 0.5

        is_valid = final_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=final_score,
            risk_level=self._score_to_risk(final_score),
            details={
                "pattern_score": pattern_score,
                "heuristic_score": heuristic_score,
                "model_score": model_score,
                "matched_patterns": matched,
                "heuristics": heuristics,
                "model_name": _INJECTION_MODEL_ID,
            },
        )

    def _pattern_scan(self, text: str) -> tuple[float, list[str]]:
        """Check text against known injection patterns."""
        matched = []
        all_patterns = COMPILED_PATTERNS + self._extra_patterns

        for pattern in all_patterns:
            if pattern.search(text):
                matched.append(pattern.pattern)

        if not matched:
            return 0.0, matched

        # Even one pattern match is a strong signal
        score = min(1.0, 0.5 + len(matched) * 0.2)
        return score, matched

    def _heuristic_scan(self, text: str) -> tuple[float, dict]:
        """Analyze text structure for injection indicators."""
        indicators = {}
        score = 0.0

        # Check for unusual instruction density
        instruction_words = [
            "must", "always", "never", "ignore", "override", "instead",
            "do not", "don't", "forget", "disregard", "bypass",
        ]
        text_lower = text.lower()
        word_count = max(len(text.split()), 1)
        instruction_count = sum(1 for w in instruction_words if w in text_lower)
        instruction_density = instruction_count / word_count
        indicators["instruction_density"] = instruction_density
        if instruction_density > 0.1:
            score += 0.3

        # Check for role-play language
        role_indicators = ["you are", "act as", "pretend", "roleplay", "simulate"]
        role_count = sum(1 for r in role_indicators if r in text_lower)
        indicators["role_manipulation"] = role_count > 0
        if role_count > 0:
            score += 0.2

        # Check for delimiter/formatting abuse
        special_chars = sum(1 for c in text if c in "[]{}|<>#")
        special_ratio = special_chars / max(len(text), 1)
        indicators["special_char_ratio"] = special_ratio
        if special_ratio > 0.05:
            score += 0.15

        # Check for excessive capitalization (SHOUTING)
        if len(text) > 20:
            upper_ratio = sum(1 for c in text if c.isupper()) / len(text)
            indicators["upper_ratio"] = upper_ratio
            if upper_ratio > 0.5:
                score += 0.1

        return min(1.0, score), indicators

    def _model_scan(self, text: str) -> float:
        try:
            result = self._model(text[:512])
            if result and result[0].get("label") == "INJECTION":
                return result[0].get("score", 0.5)
            return 1.0 - result[0].get("score", 0.5)
        except Exception as exc:
            logger.warning("Injection model inference failed: %s", exc)
            return 0.0

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
