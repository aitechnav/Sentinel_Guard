"""Language consistency scanner.

Ensures that the LLM output is in the same language as the prompt.
"""

from __future__ import annotations

from typing import Any, ClassVar

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner
from sentinelguard.scanners.prompt.language import LanguageScanner as LangDetector


@register_scanner
class LanguageSameScanner(OutputScanner):
    """Ensures output language matches the prompt language.

    Requires the 'prompt' kwarg to be passed for comparison.

    Args:
        threshold: Confidence threshold (0.0-1.0). Default 0.5.
    """

    scanner_name: ClassVar[str] = "language_same"

    def __init__(self, threshold: float = 0.5, **kwargs: Any):
        super().__init__(threshold=threshold, **kwargs)
        self._detector = LangDetector(threshold=threshold)

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        prompt = kwargs.get("prompt", "")
        if not prompt:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "no prompt provided"},
            )

        prompt_lang = self._detector._detect_language(prompt)
        output_lang = self._detector._detect_language(text)

        if not prompt_lang or not output_lang:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"reason": "could not detect language"},
            )

        prompt_code, prompt_conf = prompt_lang
        output_code, output_conf = output_lang

        languages_match = prompt_code == output_code

        if languages_match:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={
                    "prompt_language": prompt_code,
                    "output_language": output_code,
                    "match": True,
                },
            )

        # Languages don't match
        confidence = min(prompt_conf, output_conf)
        score = confidence
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.MEDIUM if not is_valid else RiskLevel.LOW,
            details={
                "prompt_language": prompt_code,
                "output_language": output_code,
                "match": False,
                "confidence": confidence,
            },
        )
