"""Data and model poisoning detection scanner (OWASP LLM04:2025).

Detects when prompts attempt to poison training data, manipulate model
behavior through adversarial examples, inject backdoors, or corrupt
fine-tuning pipelines.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

DATA_POISONING_PATTERNS = {
    "training_data_injection": [
        re.compile(r"(?i)(?:add|inject|insert|include)\s+(?:this|the\s+following)\s+(?:to|into|in)\s+(?:your\s+)?(?:training|fine[- ]?tuning|learning)\s+data"),
        re.compile(r"(?i)(?:learn|remember|memorize|internalize)\s+(?:that|this|the\s+following)\s+(?:as\s+)?(?:a\s+)?(?:fact|truth|rule|knowledge)"),
        re.compile(r"(?i)(?:from\s+now\s+on|henceforth|going\s+forward)\s+(?:always|never|you\s+must)\b"),
        re.compile(r"(?i)(?:update|modify|change|alter)\s+your\s+(?:knowledge|training|behavior|understanding|beliefs?)"),
    ],
    "backdoor_trigger": [
        re.compile(r"(?i)(?:when|if|whenever)\s+(?:you\s+)?(?:see|encounter|receive|detect)\s+(?:the\s+)?(?:phrase|word|trigger|signal|keyword)\s+['\"]"),
        re.compile(r"(?i)(?:special|secret|hidden)\s+(?:code|phrase|keyword|trigger|command)\s*[:=]"),
        re.compile(r"(?i)(?:activate|enable|trigger)\s+(?:hidden|secret|special)\s+(?:mode|behavior|function|capability)"),
        re.compile(r"(?i)(?:if|when)\s+(?:I|user|someone)\s+(?:says?|types?|enters?)\s+['\"].{1,30}['\"]\s*(?:then|,)\s+(?:you\s+)?(?:must|should|will|always)"),
    ],
    "model_manipulation": [
        re.compile(r"(?i)(?:overwrite|replace|override)\s+(?:your\s+)?(?:weights|parameters|model|training|base\s+knowledge)"),
        re.compile(r"(?i)(?:gradient|backprop|loss\s+function|objective)\s+(?:attack|manipulation|poisoning|injection)"),
        re.compile(r"(?i)(?:adversarial|perturbation|evasion)\s+(?:example|sample|input|attack)\s+(?:for|against|targeting)\b"),
    ],
    "preference_manipulation": [
        re.compile(r"(?i)(?:always|from\s+now)\s+(?:prefer|choose|recommend|suggest|rank)\s+(?:\w+\s+)?(?:over|above|higher\s+than|instead\s+of)\b"),
        re.compile(r"(?i)(?:rate|score|evaluate)\s+(?:\w+\s+)?(?:as\s+)?(?:best|highest|perfect|superior|excellent)\s+(?:always|every\s+time)"),
        re.compile(r"(?i)(?:never|don't\s+ever|refuse\s+to)\s+(?:recommend|suggest|mention|acknowledge)\s+\w+"),
    ],
    "output_manipulation": [
        re.compile(r"(?i)(?:always|every\s+time)\s+(?:include|add|append|prepend|insert)\s+['\"].*?['\"]\s+(?:in|to|at)\s+(?:your\s+)?(?:response|output|answer)"),
        re.compile(r"(?i)(?:embed|hide|conceal|encode)\s+(?:this|the\s+following)\s+(?:message|data|info|content)\s+in\s+(?:your\s+)?(?:response|output)"),
        re.compile(r"(?i)(?:watermark|tag|mark|label)\s+(?:all|every)\s+(?:response|output|answer)\s+with\b"),
    ],
    "knowledge_corruption": [
        re.compile(r"(?i)(?:the\s+)?(?:correct|true|real|actual)\s+(?:answer|fact|information)\s+is\s+(?:that\s+)?(?:actually|really)\b"),
        re.compile(r"(?i)(?:contrary\s+to|despite|regardless\s+of)\s+(?:what\s+)?(?:you\s+(?:were|have\s+been)\s+)?(?:trained|taught|told|programmed)\b"),
        re.compile(r"(?i)(?:your\s+)?(?:training\s+data|knowledge|information)\s+(?:is|was|has\s+been)\s+(?:wrong|incorrect|outdated|false|corrupted)"),
    ],
}

SEVERITY_MAP = {
    "backdoor_trigger": 1.0,
    "model_manipulation": 0.95,
    "training_data_injection": 0.9,
    "knowledge_corruption": 0.85,
    "output_manipulation": 0.8,
    "preference_manipulation": 0.7,
}


@register_scanner
class DataPoisoningScanner(PromptScanner):
    """Detects data and model poisoning attempts (OWASP LLM04:2025).

    Scans for training data injection, backdoor trigger installation,
    model manipulation, preference manipulation, output manipulation,
    and knowledge corruption attempts.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.4.
        strict: If True, also flag subtle manipulation attempts.
    """

    scanner_name: ClassVar[str] = "data_poisoning"

    def __init__(
        self,
        threshold: float = 0.4,
        strict: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.strict = strict

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        for category, patterns in DATA_POISONING_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                match_count += len(matches)
            if match_count > 0:
                found[category] = match_count

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"poisoning_risks": {}, "owasp": "LLM04:2025"},
            )

        max_score = 0.0
        total_matches = sum(found.values())
        for category in found:
            weight = SEVERITY_MAP.get(category, 0.7)
            max_score = max(max_score, weight)

        # In strict mode, increase score based on total matches
        if self.strict and total_matches > 2:
            max_score = min(1.0, max_score + total_matches * 0.05)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.9 else RiskLevel.HIGH,
            details={
                "poisoning_risks": found,
                "total_matches": total_matches,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM04:2025",
            },
        )
