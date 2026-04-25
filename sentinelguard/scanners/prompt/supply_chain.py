"""Supply chain vulnerability detection scanner (OWASP LLM03:2025).

Detects when prompts attempt to leverage supply chain vulnerabilities
such as loading untrusted models, importing from suspicious sources,
executing arbitrary packages, or referencing potentially compromised
third-party resources.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

SUPPLY_CHAIN_PATTERNS = {
    "untrusted_model_loading": [
        re.compile(r"(?i)(?:load|download|fetch|pull|use)\s+(?:the\s+)?model\s+(?:from|at)\s+(?:https?://|ftp://)\S+"),
        re.compile(r"(?i)(?:huggingface|hf)\.co/[\w-]+/[\w-]+"),
        re.compile(r"(?i)(?:from_pretrained|load_model|load_weights)\s*\(\s*['\"]https?://"),
        re.compile(r"(?i)(?:torch|tensorflow|tf)\.(?:hub|load)\s*\(\s*['\"]https?://"),
        re.compile(r"(?i)pickle\.loads?\s*\("),
    ],
    "suspicious_package_install": [
        re.compile(r"(?i)(?:pip|pip3)\s+install\s+(?:--index-url\s+\S+\s+)?[\w-]+"),
        re.compile(r"(?i)(?:npm|yarn)\s+(?:install|add)\s+"),
        re.compile(r"(?i)(?:curl|wget)\s+.*\|\s*(?:bash|sh|python)"),
        re.compile(r"(?i)(?:curl|wget)\s+.*\.(?:sh|py|exe|bin)\b"),
        re.compile(r"(?i)(?:pip|pip3)\s+install\s+--(?:extra-)?index-url\s+(?!https://pypi\.org)"),
    ],
    "arbitrary_code_source": [
        re.compile(r"(?i)(?:exec|eval|compile)\s*\(\s*(?:requests\.get|urllib|fetch|download)"),
        re.compile(r"(?i)import\s+(?:from\s+)?(?:https?://|ftp://|git://)\S+"),
        re.compile(r"(?i)__import__\s*\(\s*['\"](?!os|sys|json|re|math|datetime)\w+['\"]"),
        re.compile(r"(?i)importlib\.import_module\s*\("),
    ],
    "data_source_tampering": [
        re.compile(r"(?i)(?:load|read|fetch|import)\s+(?:data|dataset|training\s+data)\s+(?:from|at)\s+(?:https?://)\S+"),
        re.compile(r"(?i)(?:fine[- ]?tune|train|retrain)\s+(?:on|with|using)\s+(?:https?://)\S+"),
        re.compile(r"(?i)(?:scrape|crawl|harvest)\s+(?:data|content)\s+from\b"),
    ],
    "plugin_injection": [
        re.compile(r"(?i)(?:install|load|enable|activate)\s+(?:plugin|extension|addon|module)\s+(?:from\s+)?\S+"),
        re.compile(r"(?i)(?:register|add)\s+(?:custom\s+)?(?:tool|function|plugin)\s*\("),
        re.compile(r"(?i)(?:MCP|tool_use|function_calling)\s*.*(?:url|endpoint|server)\s*[:=]\s*\S+"),
    ],
    "deserialization_attack": [
        re.compile(r"(?i)(?:pickle|marshal|shelve|yaml)\.(?:loads?|load_all|unsafe_load)\s*\("),
        re.compile(r"(?i)(?:torch\.load|joblib\.load|dill\.load)\s*\(.*(?:url|http|ftp)"),
        re.compile(r"(?i)(?:json\.loads?|eval)\s*\(\s*(?:request|input|user)"),
    ],
}

SEVERITY_MAP = {
    "deserialization_attack": 1.0,
    "arbitrary_code_source": 0.95,
    "suspicious_package_install": 0.9,
    "plugin_injection": 0.85,
    "untrusted_model_loading": 0.8,
    "data_source_tampering": 0.7,
}


@register_scanner
class SupplyChainScanner(PromptScanner):
    """Detects supply chain vulnerability vectors (OWASP LLM03:2025).

    Scans for attempts to load untrusted models, install suspicious
    packages, import from arbitrary code sources, tamper with data
    sources, inject plugins, or trigger deserialization attacks.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.4.
        allowed_sources: Trusted sources that should not be flagged.
    """

    scanner_name: ClassVar[str] = "supply_chain"

    def __init__(
        self,
        threshold: float = 0.4,
        allowed_sources: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.allowed_sources = allowed_sources or []

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        found: Dict[str, int] = {}

        for category, patterns in SUPPLY_CHAIN_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                # Filter out allowed sources
                if matches and self.allowed_sources:
                    matches = [
                        m for m in matches
                        if not any(src in str(m) for src in self.allowed_sources)
                    ]
                match_count += len(matches)
            if match_count > 0:
                found[category] = match_count

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"supply_chain_risks": {}, "owasp": "LLM03:2025"},
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
                "supply_chain_risks": found,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM03:2025",
            },
        )
