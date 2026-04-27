"""Language detection scanner.

Identifies the language of input text and optionally restricts
to allowed languages.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

# Common words by language for basic detection
LANGUAGE_MARKERS: Dict[str, List[str]] = {
    "en": [
        "the", "is", "are", "was", "were", "have", "has", "had", "been", "being",
        "will", "would", "could", "should", "can", "may", "might", "shall",
        "this", "that", "these", "those", "with", "from", "into", "about",
    ],
    "es": [
        "el", "la", "los", "las", "es", "son", "fue", "ser", "estar",
        "tiene", "para", "como", "pero", "por", "con", "una", "este",
    ],
    "fr": [
        "le", "la", "les", "est", "sont", "avoir", "faire", "avec",
        "pour", "dans", "pas", "une", "des", "que", "sur", "mais",
    ],
    "de": [
        "der", "die", "das", "ist", "sind", "haben", "sein", "werden",
        "mit", "und", "ich", "nicht", "ein", "eine", "auf", "auch",
    ],
    "it": [
        "il", "lo", "la", "gli", "sono", "essere", "avere", "fare",
        "con", "per", "che", "non", "una", "questo", "anche", "come",
    ],
    "pt": [
        "o", "os", "as", "um", "uma", "ser", "estar", "ter", "fazer",
        "com", "para", "por", "que", "nao", "mais", "como", "muito",
    ],
    "zh": [],  # Detected by character range
    "ja": [],  # Detected by character range
    "ko": [],  # Detected by character range
    "ar": [],  # Detected by character range
}

# Unicode ranges for script detection
SCRIPT_RANGES = {
    "zh": [(0x4E00, 0x9FFF), (0x3400, 0x4DBF)],  # CJK Unified Ideographs
    "ja": [(0x3040, 0x309F), (0x30A0, 0x30FF)],  # Hiragana + Katakana
    "ko": [(0xAC00, 0xD7AF), (0x1100, 0x11FF)],  # Hangul
    "ar": [(0x0600, 0x06FF), (0x0750, 0x077F)],  # Arabic
    "ru": [(0x0400, 0x04FF)],  # Cyrillic
    "hi": [(0x0900, 0x097F)],  # Devanagari
    "th": [(0x0E00, 0x0E7F)],  # Thai
}


@register_scanner
class LanguageScanner(PromptScanner):
    """Detects the language of text and optionally enforces allowed languages.

    Args:
        threshold: Confidence threshold (0.0-1.0). Default 0.5.
        allowed_languages: List of allowed language codes. None = all.
        min_length: Minimum text length for detection. Default 10.
    """

    scanner_name: ClassVar[str] = "language"

    def __init__(
        self,
        threshold: float = 0.5,
        allowed_languages: Optional[List[str]] = None,
        min_length: int = 10,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.allowed_languages = allowed_languages
        self.min_length = min_length

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        if len(text) < self.min_length:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "text_too_short"},
            )

        detected = self._detect_language(text)

        if not detected:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"detected_language": "unknown", "confidence": 0.0},
            )

        lang, confidence = detected

        # Check against allowed languages
        if self.allowed_languages is not None:
            is_allowed = lang in self.allowed_languages
            is_valid = is_allowed or confidence < self.threshold
        else:
            is_valid = True

        return ScanResult(
            is_valid=is_valid,
            score=1.0 - confidence if not is_valid else 0.0,
            risk_level=RiskLevel.LOW if is_valid else RiskLevel.MEDIUM,
            details={
                "detected_language": lang,
                "confidence": confidence,
                "is_allowed": is_valid,
            },
        )

    def _detect_language(self, text: str) -> Optional[tuple[str, float]]:
        """Detect language using script analysis and word frequency."""
        # First check script-based detection
        script_lang = self._detect_by_script(text)
        if script_lang:
            return script_lang

        # Fall back to word-based detection
        return self._detect_by_words(text)

    def _detect_by_script(self, text: str) -> Optional[tuple[str, float]]:
        """Detect language by Unicode script ranges."""
        script_counts: Dict[str, int] = {}
        total_chars = 0

        for char in text:
            cp = ord(char)
            for lang, ranges in SCRIPT_RANGES.items():
                for start, end in ranges:
                    if start <= cp <= end:
                        script_counts[lang] = script_counts.get(lang, 0) + 1
                        total_chars += 1
                        break

        if not script_counts or total_chars < 3:
            return None

        best_lang = max(script_counts, key=script_counts.get)
        confidence = script_counts[best_lang] / max(total_chars, 1)
        return best_lang, min(1.0, confidence)

    def _detect_by_words(self, text: str) -> Optional[tuple[str, float]]:
        """Detect language by common word frequency."""
        words = set(re.findall(r"\b\w+\b", text.lower()))
        if not words:
            return None

        scores: Dict[str, float] = {}
        for lang, markers in LANGUAGE_MARKERS.items():
            if not markers:
                continue
            matches = len(words & set(markers))
            scores[lang] = matches / len(markers)

        if not scores:
            return None

        best_lang = max(scores, key=scores.get)
        confidence = scores[best_lang]

        if confidence < 0.1:
            return None

        return best_lang, min(1.0, confidence * 2)
