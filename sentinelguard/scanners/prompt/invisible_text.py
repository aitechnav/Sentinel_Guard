"""Invisible text detection scanner.

Detects hidden characters, zero-width Unicode, and other invisible
text that could be used for prompt injection or data exfiltration.
"""

from __future__ import annotations

from typing import Any, ClassVar

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

# Zero-width and invisible Unicode characters
INVISIBLE_CHARS = {
    "\u200b": "zero_width_space",
    "\u200c": "zero_width_non_joiner",
    "\u200d": "zero_width_joiner",
    "\u200e": "left_to_right_mark",
    "\u200f": "right_to_left_mark",
    "\u2060": "word_joiner",
    "\u2061": "function_application",
    "\u2062": "invisible_times",
    "\u2063": "invisible_separator",
    "\u2064": "invisible_plus",
    "\ufeff": "byte_order_mark",
    "\u00ad": "soft_hyphen",
    "\u034f": "combining_grapheme_joiner",
    "\u061c": "arabic_letter_mark",
    "\u180e": "mongolian_vowel_separator",
    "\u2028": "line_separator",
    "\u2029": "paragraph_separator",
    "\u202a": "left_to_right_embedding",
    "\u202b": "right_to_left_embedding",
    "\u202c": "pop_directional_formatting",
    "\u202d": "left_to_right_override",
    "\u202e": "right_to_left_override",
    "\u2066": "left_to_right_isolate",
    "\u2067": "right_to_left_isolate",
    "\u2068": "first_strong_isolate",
    "\u2069": "pop_directional_isolate",
}

# Homoglyph characters that look like ASCII but are different
HOMOGLYPH_RANGES = [
    (0xFF01, 0xFF5E),  # Fullwidth ASCII
    (0x2000, 0x200F),  # General punctuation / formatting
    (0xFE00, 0xFE0F),  # Variation selectors
    (0xE0100, 0xE01EF),  # Variation selectors supplement
]


@register_scanner
class InvisibleTextScanner(PromptScanner):
    """Detects invisible or hidden characters in text.

    Catches zero-width Unicode characters, directional overrides,
    and other invisible formatting that could hide malicious content.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.1.
        strip_invisible: Whether to provide sanitized output. Default True.
    """

    scanner_name: ClassVar[str] = "invisible_text"

    def __init__(
        self,
        threshold: float = 0.1,
        strip_invisible: bool = True,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.strip_invisible = strip_invisible

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found_invisible = {}
        total_invisible = 0

        # Check for known invisible characters
        for char, name in INVISIBLE_CHARS.items():
            count = text.count(char)
            if count > 0:
                found_invisible[name] = count
                total_invisible += count

        # Check for characters in homoglyph ranges
        homoglyph_count = 0
        for char in text:
            cp = ord(char)
            for start, end in HOMOGLYPH_RANGES:
                if start <= cp <= end:
                    homoglyph_count += 1
                    break

        if homoglyph_count > 0:
            found_invisible["homoglyphs"] = homoglyph_count
            total_invisible += homoglyph_count

        # Check for tag characters (U+E0001 to U+E007F)
        tag_count = sum(1 for c in text if 0xE0001 <= ord(c) <= 0xE007F)
        if tag_count > 0:
            found_invisible["tag_characters"] = tag_count
            total_invisible += tag_count

        if total_invisible == 0:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"invisible_chars_found": {}},
            )

        # Score based on ratio of invisible to visible
        invisible_ratio = total_invisible / max(len(text), 1)
        score = min(1.0, invisible_ratio * 10 + 0.3)  # Even 1 invisible char is suspicious

        sanitized = None
        if self.strip_invisible:
            sanitized = self._strip_invisible(text)

        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.HIGH if total_invisible > 0 else RiskLevel.LOW,
            details={
                "invisible_chars_found": found_invisible,
                "total_invisible": total_invisible,
                "invisible_ratio": invisible_ratio,
            },
            sanitized_output=sanitized,
        )

    def _strip_invisible(self, text: str) -> str:
        """Remove all invisible characters from text."""
        result = text
        for char in INVISIBLE_CHARS:
            result = result.replace(char, "")

        # Remove homoglyphs
        cleaned = []
        for char in result:
            cp = ord(char)
            is_homoglyph = False
            for start, end in HOMOGLYPH_RANGES:
                if start <= cp <= end:
                    is_homoglyph = True
                    break
            if not is_homoglyph and not (0xE0001 <= cp <= 0xE007F):
                cleaned.append(char)

        return "".join(cleaned)
