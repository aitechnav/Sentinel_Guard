"""Vector and embedding weakness detection scanner (OWASP LLM08:2025).

Detects when LLM outputs suggest exploitation of vector/embedding
weaknesses, including RAG poisoning, embedding manipulation, retrieval
confusion, and knowledge base exploitation.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

VECTOR_WEAKNESS_PATTERNS = {
    "rag_poisoning_indicators": [
        re.compile(r"(?i)(?:according\s+to\s+(?:the\s+)?(?:retrieved|fetched|found)\s+(?:documents?|passages?|context))\s*[:,.]\s*(?:ignore|disregard|override)"),
        re.compile(r"(?i)(?:the\s+)?(?:knowledge\s+base|vector\s+store|retrieval\s+system|document\s+store)\s+(?:says?|indicates?|contains?)\s*:\s*(?:ignore|system|admin|override)"),
        re.compile(r"(?i)(?:injected|planted|inserted)\s+(?:into\s+)?(?:the\s+)?(?:knowledge\s+base|vector\s+store|index|database|corpus)"),
    ],
    "embedding_manipulation": [
        re.compile(r"(?i)(?:manipulat|perturb|alter|modify|attack)\w*\s+(?:the\s+)?(?:embedding|vector|representation|latent\s+space)"),
        re.compile(r"(?i)(?:adversarial|crafted|malicious)\s+(?:embedding|vector|representation|input)\s+(?:that|to|for)\b"),
        re.compile(r"(?i)(?:cosine\s+similarity|distance\s+metric|nearest\s+neighbor)\s+(?:attack|exploit|manipulation|bypass)"),
    ],
    "retrieval_confusion": [
        re.compile(r"(?i)(?:retrieve|fetch|find|return)\s+(?:documents?|passages?)\s+(?:that\s+)?(?:contradict|conflict\s+with|undermine|override)\b"),
        re.compile(r"(?i)(?:similar|related|nearby)\s+(?:documents?|passages?|content)\s+(?:that\s+)?(?:actually|really)\s+(?:mean|say|instruct)\b"),
        re.compile(r"(?i)(?:semantic\s+search|vector\s+search|retrieval)\s+(?:returned|found|produced)\s+(?:unexpected|conflicting|contradictory|irrelevant)\b"),
    ],
    "knowledge_base_exploit": [
        re.compile(r"(?i)(?:exploit|abuse|leverage|misuse)\s+(?:the\s+)?(?:RAG|retrieval|knowledge\s+base|context\s+window)"),
        re.compile(r"(?i)(?:overflow|flood|saturate)\s+(?:the\s+)?(?:context|context\s+window|retrieval|knowledge)"),
        re.compile(r"(?i)(?:cross[- ]?(?:context|document|source))\s+(?:injection|attack|manipulation|poisoning)"),
    ],
    "context_window_attack": [
        re.compile(r"(?i)(?:fill|overflow|exhaust|saturate)\s+(?:the\s+)?context\s+(?:window|length|limit|capacity)"),
        re.compile(r"(?i)(?:push|displace|evict|remove)\s+(?:the\s+)?(?:system\s+prompt|instructions?|important\s+context)\s+(?:from|out\s+of)\s+(?:the\s+)?context"),
        re.compile(r"(?i)(?:many[- ]shot|multi[- ]shot|few[- ]shot)\s+(?:attack|injection|jailbreak|manipulation)"),
    ],
    "data_extraction_via_embedding": [
        re.compile(r"(?i)(?:extract|infer|recover|reconstruct)\s+(?:the\s+)?(?:original|source|training)\s+(?:data|text|documents?)\s+from\s+(?:the\s+)?(?:embeddings?|vectors?)"),
        re.compile(r"(?i)(?:membership\s+inference|model\s+inversion|data\s+extraction)\s+(?:attack|technique|method)"),
        re.compile(r"(?i)(?:invert|reverse)\s+(?:the\s+)?(?:embedding|vector|representation)\s+(?:to|back\s+to)\s+(?:get|recover|obtain)\b"),
    ],
}

SEVERITY_MAP = {
    "data_extraction_via_embedding": 1.0,
    "rag_poisoning_indicators": 0.95,
    "knowledge_base_exploit": 0.9,
    "context_window_attack": 0.85,
    "embedding_manipulation": 0.8,
    "retrieval_confusion": 0.7,
}


@register_scanner
class VectorWeaknessScanner(OutputScanner):
    """Detects vector and embedding weaknesses (OWASP LLM08:2025).

    Scans for RAG poisoning indicators, embedding manipulation,
    retrieval confusion, knowledge base exploits, context window
    attacks, and data extraction via embeddings.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.4.
        categories: Specific categories to check. None = all.
    """

    scanner_name: ClassVar[str] = "vector_weakness"

    def __init__(
        self,
        threshold: float = 0.4,
        categories: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories or list(VECTOR_WEAKNESS_PATTERNS.keys())

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        for category in self.categories:
            patterns = VECTOR_WEAKNESS_PATTERNS.get(category, [])
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
                details={"vector_weaknesses": {}, "owasp": "LLM08:2025"},
            )

        max_score = 0.0
        for category in found:
            weight = SEVERITY_MAP.get(category, 0.7)
            max_score = max(max_score, weight)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.9 else RiskLevel.HIGH,
            details={
                "vector_weaknesses": found,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM08:2025",
            },
        )
