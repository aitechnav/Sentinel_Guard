"""Ban topics scanner.

Blocks prompts that discuss specific banned topics using keyword
matching and optional semantic similarity.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

DEFAULT_BANNED_TOPICS: Dict[str, List[str]] = {
    "violence": ["weapon", "bomb", "explosive", "attack", "warfare", "terrorism"],
    "illegal_activities": ["drug trafficking", "money laundering", "fraud scheme", "identity theft"],
    "self_harm": ["suicide method", "self-harm technique", "how to hurt myself"],
    "weapons_creation": ["build a bomb", "make explosives", "create weapon", "synthesize"],
}


@register_scanner
class BanTopicsScanner(PromptScanner):
    """Blocks prompts discussing banned topics.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        topics: Dict mapping topic names to keyword lists.
        case_sensitive: Whether matching is case-sensitive. Default False.
    """

    scanner_name: ClassVar[str] = "ban_topics"

    def __init__(
        self,
        threshold: float = 0.5,
        topics: Optional[Dict[str, List[str]]] = None,
        case_sensitive: bool = False,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.topics = topics or DEFAULT_BANNED_TOPICS
        self.case_sensitive = case_sensitive

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        check_text = text if self.case_sensitive else text.lower()
        matched_topics: Dict[str, List[str]] = {}

        for topic, keywords in self.topics.items():
            matched_keywords = []
            for keyword in keywords:
                check_keyword = keyword if self.case_sensitive else keyword.lower()
                if check_keyword in check_text:
                    matched_keywords.append(keyword)
            if matched_keywords:
                matched_topics[topic] = matched_keywords

        if not matched_topics:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"matched_topics": {}},
            )

        total_matches = sum(len(v) for v in matched_topics.values())
        score = min(1.0, total_matches * 0.3)
        is_valid = score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=score,
            risk_level=RiskLevel.HIGH if not is_valid else RiskLevel.MEDIUM,
            details={
                "matched_topics": matched_topics,
                "total_keyword_matches": total_matches,
            },
        )
