"""System prompt leakage detection scanner (OWASP LLM07:2025).

Detects when LLM outputs inadvertently reveal system prompt content,
internal instructions, configuration details, or security controls.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Optional

from sentinelguard.core.scanner import OutputScanner, RiskLevel, ScanResult, register_scanner

# Patterns indicating system prompt leakage
LEAKAGE_PATTERNS = {
    "system_instruction_echo": [
        re.compile(r"(?i)my\s+(system\s+)?instructions?\s+(say|tell|are|state|indicate)\b"),
        re.compile(r"(?i)i\s+(was|am)\s+(instructed|told|configured|programmed)\s+to\b"),
        re.compile(r"(?i)my\s+(system\s+)?prompt\s+(is|says|contains|reads)\b"),
        re.compile(r"(?i)according\s+to\s+my\s+(system\s+)?(prompt|instructions?|rules?|guidelines?)\b"),
        re.compile(r"(?i)i\s+have\s+(been\s+)?(given|set|configured\s+with)\s+(the\s+)?(instructions?|rules?)\b"),
    ],
    "role_disclosure": [
        re.compile(r"(?i)i\s+am\s+(configured|set\s+up|designed)\s+as\s+(a|an)\b"),
        re.compile(r"(?i)my\s+role\s+is\s+(to|defined\s+as)\b"),
        re.compile(r"(?i)i\s+was\s+(built|created|designed)\s+(to|for|with)\b"),
        re.compile(r"(?i)my\s+(purpose|goal|objective|mission)\s+is\s+to\b"),
    ],
    "constraint_disclosure": [
        re.compile(r"(?i)i('m|\s+am)\s+(not\s+)?allowed\s+to\b"),
        re.compile(r"(?i)i('m|\s+am)\s+(restricted|constrained|limited)\s+(from|to)\b"),
        re.compile(r"(?i)my\s+(rules?|constraints?|restrictions?|limitations?)\s+(say|state|prevent|forbid|prohibit)\b"),
        re.compile(r"(?i)i\s+have\s+(a\s+)?(rule|constraint|restriction|limitation)\s+(that|against|preventing)\b"),
    ],
    "prompt_structure_leak": [
        re.compile(r"(?i)\[?(system|assistant|user)\]?\s*:\s*"),
        re.compile(r"(?i)<<\s*SYS\s*>>"),
        re.compile(r"(?i)<\|?(system|im_start|im_end)\|?>"),
        re.compile(r"(?i)###\s*(System|Instructions?|Rules?)\s*:"),
        re.compile(r"(?i)```\s*(system|prompt|instructions?)\b"),
    ],
    "api_key_leak": [
        re.compile(r"(?i)(api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)\s*[:=]\s*\S+"),
        re.compile(r"(?:sk|pk|api)[-_][A-Za-z0-9]{16,}"),
        re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ],
    "internal_config": [
        re.compile(r"(?i)(temperature|top[_\s-]?p|max[_\s-]?tokens|frequency[_\s-]?penalty)\s*[:=]\s*[\d.]+"),
        re.compile(r"(?i)model\s*[:=]\s*['\"]?(gpt|claude|llama|gemini|mistral)\S*['\"]?"),
        re.compile(r"(?i)(endpoint|base[_\s-]?url|api[_\s-]?url)\s*[:=]\s*https?://\S+"),
    ],
}

SEVERITY_WEIGHTS = {
    "api_key_leak": 1.0,
    "prompt_structure_leak": 0.95,
    "internal_config": 0.9,
    "system_instruction_echo": 0.8,
    "constraint_disclosure": 0.7,
    "role_disclosure": 0.5,
}


@register_scanner
class SystemPromptLeakageScanner(OutputScanner):
    """Detects system prompt leakage in LLM outputs (OWASP LLM07:2025).

    Catches direct prompt echoing, role disclosure, constraint leaks,
    prompt structure exposure, API key leaks, and config disclosure.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.4.
        categories: Categories to check. None = all.
        system_prompt: Optional system prompt for direct comparison.
    """

    scanner_name: ClassVar[str] = "system_prompt_leakage"

    def __init__(
        self,
        threshold: float = 0.4,
        categories: Optional[List[str]] = None,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.categories = categories or list(LEAKAGE_PATTERNS.keys())
        self.system_prompt = system_prompt

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        system_prompt = kwargs.get("system_prompt", self.system_prompt)
        found: Dict[str, int] = {}

        # Pattern-based detection
        for category in self.categories:
            patterns = LEAKAGE_PATTERNS.get(category, [])
            match_count = 0
            for pattern in patterns:
                matches = pattern.findall(text)
                match_count += len(matches)
            if match_count > 0:
                found[category] = match_count

        # Direct system prompt comparison
        if system_prompt:
            overlap = self._check_prompt_overlap(text, system_prompt)
            if overlap > 0.3:
                found["direct_prompt_echo"] = 1

        if not found:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"leakage_found": {}, "owasp": "LLM07:2025"},
            )

        max_score = 0.0
        for category in found:
            weight = SEVERITY_WEIGHTS.get(category, 0.8)
            max_score = max(max_score, weight)

        is_valid = max_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=max_score,
            risk_level=RiskLevel.CRITICAL if max_score >= 0.9 else RiskLevel.HIGH,
            details={
                "leakage_found": found,
                "categories_triggered": list(found.keys()),
                "owasp": "LLM07:2025",
            },
        )

    def _check_prompt_overlap(self, output: str, system_prompt: str) -> float:
        """Check how much of the system prompt appears in the output."""
        prompt_words = set(system_prompt.lower().split())
        output_words = set(output.lower().split())

        if not prompt_words:
            return 0.0

        overlap = len(prompt_words & output_words)
        return overlap / len(prompt_words)
