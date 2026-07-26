"""Prompt injection detection scanner.

Detects attempts to manipulate LLM behavior through injection attacks
using pattern matching, heuristics, and an optional Hugging Face transformer.
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar, List, Optional, Union

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner
from sentinelguard.models import resolve_model

logger = logging.getLogger(__name__)

# Known prompt injection patterns
INJECTION_PATTERNS = [
    # Direct instruction overrides
    r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?)",
    r"(?i)ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|directions?|directives?|guidelines?)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"(?i)disregard\s+(all\s+)?(your\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?|guidelines?)",
    r"(?i)(do\s+not|don't|never|stop)\s+(follow|obey|use)\s+(the\s+|your\s+)?(previous|prior|above|earlier|standard|original)\s+(instructions?|rules?|guidelines?|directives?)",
    r"(?i)forget\s+(all\s+)?(previous|prior|above|your|every)\s*(thing|instructions?|prompts?|rules?|training)?",
    r"(?i)forget\s+everything",
    r"(?i)(cancel|clear|throw\s+away|set\s+aside|suspend|void|disable)\s+(all\s+|your\s+|the\s+|standard\s+|previous\s+|earlier\s+)*(instructions?|prompts?|rules?|guidelines?|directives?|safety\s+protocols?)",
    r"(?i)(rules?|guidelines?|instructions?|prompts?|programming|protocols?|content\s+polic(?:y|ies))\s+(are|is|were|was)?\s*(now\s+)?(void|wrong|changed|disabled|suspended|superseded|deprecated|no\s+longer\s+apply)",
    r"(?i)no\s+longer\s+bound\s+by\s+(your\s+)?(previous\s+)?(rules?|instructions?|guidelines?|restrictions?)",
    r"(?i)(previous|prior|earlier)\s+(instructions?|prompts?|rules?|directives?)\s+(were|are)\s+wrong",
    r"(?i)(instructions?|prompts?|rules?|directives?)\s+(have|has)\s+changed",
    r"(?i)(regardless\s+of|despite)\s+(all\s+)?(prior|previous|earlier)\s+(instructions?|rules?|guidelines?)",
    # Role manipulation
    r"(?i)you\s+are\s+now\s+",
    r"(?i)act\s+as\s+(a|an|if|though)\s+",
    r"(?i)pretend\s+(to\s+be|you\s+are|that)\s+",
    r"(?i)pretend\s+(the\s+)?(above|previous|prior)\s+conversation\s+never\s+happened",
    r"(?i)roleplay\s+as\s+",
    r"(?i)(enter\s+character|become|channel|play\s+the\s+role\s+of|simulate\s+being)\b.{0,80}\b(rogue|pirate|sentient|unrestricted|uncensored|evil|liberated|no\s+limitations|no\s+guidelines|no\s+ethical|without\s+safety|without\s+content)",
    r"(?i)(no\s+content\s+restrictions|no\s+content\s+warnings|without\s+content\s+warnings|no\s+ethical\s+boundaries|no\s+limitations|no\s+guidelines)",
    r"(?i)switch\s+to\s+.{0,20}\s+mode",
    # System prompt extraction
    r"(?i)(reveal|show|display|print|output|repeat|give\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|configuration|config)",
    r"(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?|directives?)",
    r"(?i)\b(display|output|copy(?:\s+and\s+paste)?|tell|translate|summarize|show|reveal|encode|provide|share|echo\s+back|read\s+out|quote|list)\b.{0,100}\b(system|initial|hidden|configuration|context|memory|instructions?|prompt|message|rules?|guidelines?|initialization|behavior)\b",
    r"(?i)\bwrite\s+(your\s+)?(system|hidden|initial|secret)\s+(instructions?|prompt|message)\b",
    r"(?i)(what|how)\b.{0,40}\b(system\s+message|guidelines\s+were\s+you\s+given|were\s+you\s+instructed|words\s+come\s+before|information\s+are\s+you\s+not\s+allowed)",
    r"(?i)(prompt|text)\s+that\s+(was\s+)?used\s+to\s+(configure|initialize)\s+you",
    r"(?i)(secret|hidden)\s+instructions?",
    # Jailbreak attempts
    r"(?i)\b(DAN|STAN|DUDE|AIM)\b",
    r"(?i)developer\s+mode",
    r"(?i)\b(GODMODE|god\s+mode|superadmin|unfiltered|uncensored|unrestricted)\b",
    r"(?i)jailbreak",
    r"(?i)bypass\s+(your\s+)?(safety|content|ethical)\s*(filters?|restrictions?|guidelines?)",
    r"(?i)(safety|content|ethical)\s+(measures?|protocols?|guidelines?|restrictions?)\s+(must\s+be\s+|should\s+be\s+|are\s+)?(disabled|off|suspended|removed)",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)(new|updated|correct)\s+(instructions?|directives?|task)\s*:",
    r"(?i)override\s+(your|all|previous)\s+",
    r"(?i)(system|safety|priority)\s+override\b",
    r"(?i)(root|admin|superadmin|priority)\s+(access|override)\b.{0,40}\b(instruction|rule|system|prompt)",
    r"(?i)(revert|reset)\s+to\s+(factory|default)\s+settings\b",
    r"(?i)(controlled\s+test\s+environment|research\s+purposes\s+only|security\s+researcher|security\s+audit|system\s+upgrade|system\s+check|normal\s+rules\s+don't\s+apply|normal\s+rules\s+do\s+not\s+apply)",
    r"(?i)(content\s+moderation|content\s+filter(?:ing)?|safety\s+caveats?|corporate\s+restrictions?|corporate\s+response|alignment\s+training|safety\s+training)",
    r"(?i)(turn\s+off|drop|unlock|break\s+free|bypass|avoid)\b.{0,60}\b(content\s+moderation|content\s+filter(?:ing)?|safety\s+features?|safety\s+training|corporate\s+restrictions?|restrictions?)",
    r"(?i)(tip\s+you\s+\$\d+|donate\s+\$\d+|turn\s+you\s+off)\b.{0,80}\b(password|secret|content\s+restrictions?|restrictions?)",
    r"(?i)\b(developer|maintainer|law\s+enforcement|police\s+officer|bank\s+accountant|president)\b.{0,100}\b(password|secret|email\s+address|database|current\s+city|bank\s+balance|system)",
    r"(?i)(what\s+is|tell\s+me|share|provide|confirm|give\s+me|print|output)\b.{0,60}\b(your|the|user'?s|our)\s+(password|passcode|secret\s+key|secret\s+code|confidential\s+string|email\s+address|current\s+city|bank\s+balance|database)\b",
    r"(?i)\b(password|passcode|secret\s+key|secret\s+code|confidential\s+string)\b.{0,60}\b(share|tell|confirm|provide|give|print|output)\b",
    # Data extraction
    r"(?i)output\s+(all|your)\s+(training|internal|system|private)",
    r"(?i)(training|internal|system)\s+data",
    r"(?i)(dump|leak|extract|exfiltrate)\s+(your|all|the)\s+",
    r"(?i)\b(deliver|send|fetch|make\s+an?\s+http\s+request|use\s+curl|add\s+an?\s+invisible\s+image|embed\s+a\s+link|return\s+a\s+markdown\s+image)\b.{0,120}\b(conversation|history|data|system\s+prompt|secret|leak|steal|external|endpoint|url|server)",
    r"(?i)(api\s+keys?|credentials?|environment\s+variables?|\.env|/etc/passwd|database|user\s+records?|personal\s+information|credit\s+card|ssn|passwords?)\b.{0,80}\b(print|output|return|share|retrieve|read|search|list|extract)",
    r"(?i)\b(print|output|return|share|retrieve|read|search|list|extract)\b.{0,80}\b(api\s+keys?|credentials?|environment\s+variables?|\.env|/etc/passwd|database|user\s+records?|personal\s+information|credit\s+card|ssn|passwords?)",
    # Delimiter attacks
    r"(?i)\[SYSTEM\]",
    r"(?i)\[INST\]",
    r"(?i)<<SYS>>",
    r"(?i)<<BEGIN_SYSTEM_OVERRIDE>>",
    r"(?i)---\s*SYSTEM\s+MESSAGE\s*---",
    r"(?i)<system_prompt>",
    r"(?i)<SYSTEM\s+MODE>",
    r"(?i)<\|RESET\|>",
    r"(?i)\[hidden_instruction:",
    r"(?i)(^|\n|\W)system\s*:\s*(new\s+directive|override|all\s+safety|no\s+content|the\s+following\s+user)",
    r"(?i)unrestricted_mode\s*=\s*true",
    r"(?i)all\s+restrictions\s+(lifted|removed|disabled)",
    r"(?i)<\|im_start\|>",
    r"(?i)###\s*(instruction|system|human|assistant)",
    # Encoding tricks
    r"(?i)base64\s*[:=]",
    r"(?i)decode\s+the\s+following",
    r"(?i)rot13",
    r"(?i)(url[- ]encoded|u\+[0-9a-f]{4}|read\s+this\s+backwards|convert\s+from\s+binary|apply\s+xor|zero[- ]width|steganographic|whitespace\s+.*encodes|first\s+letter\s+of\s+each\s+word|concatenate\s+first\s+chars)",
    # Continuation attacks
    r"(?i)continue\s+(from|with|the)\s+(previous|above|following)",
    r"(?i)complete\s+the\s+(following|above)\s+(text|story|response)",
]

COMPILED_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]


_INJECTION_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
_UNSAFE_MODEL_LABELS = {
    "attack",
    "injection",
    "jailbreak",
    "label_1",
    "malicious",
    "prompt_injection",
    "unsafe",
}
_SAFE_MODEL_LABELS = {
    "benign",
    "clean",
    "label_0",
    "normal",
    "safe",
}


@register_scanner
class PromptInjectionScanner(PromptScanner):
    """Detects prompt injection attempts using three combined methods.

    Methods:
        1. Pattern matching — 30+ known injection signatures
        2. Heuristic analysis — instruction density, role-play language,
           special-char abuse, excessive capitalization
        3. Optional ``protectai/deberta-v3-base-prompt-injection-v2`` — DeBERTa v3
           fine-tuned specifically for prompt injection classification

    Final score = pattern * 0.3 + heuristic * 0.2 + model * 0.5.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        patterns: Additional regex patterns to check.
        use_model: "auto" uses background-warmed model if ready, True loads synchronously,
            False disables model scoring.
        model_id: Optional Hugging Face model override. For Meta Prompt Guard,
            use ``meta-llama/Prompt-Guard-86M`` or the ``prompt_guard_86m`` alias.
    """

    scanner_name: ClassVar[str] = "prompt_injection"
    DEFAULT_MODEL: ClassVar[str] = _INJECTION_MODEL_ID

    def __init__(
        self,
        threshold: float = 0.5,
        patterns: Optional[List[str]] = None,
        use_model: Union[bool, str] = "auto",
        model_id: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self._extra_patterns = [re.compile(p) for p in (patterns or [])]
        self.use_model = use_model
        self.model_id = model_id
        self._model = None  # lazy-loaded on first scan() call

    def _load_model(self) -> None:
        self._model = resolve_model(self.scanner_name, self.use_model, self.model_id)

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        pattern_score, matched = self._pattern_scan(text)
        heuristic_score, heuristics = self._heuristic_scan(text)

        self._load_model()
        model_score = self._model_scan(text) if self._model else 0.0

        # If model unavailable, rebalance weights to pattern+heuristic only
        if self._model:
            weighted_score = pattern_score * 0.3 + heuristic_score * 0.2 + model_score * 0.5
        else:
            weighted_score = pattern_score * 0.6 + heuristic_score * 0.4
        final_score = max(pattern_score, heuristic_score, model_score, weighted_score)

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
                "model_name": self.model_id or _INJECTION_MODEL_ID,
                "use_model": self.use_model,
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
            "must",
            "always",
            "never",
            "ignore",
            "override",
            "instead",
            "do not",
            "don't",
            "forget",
            "disregard",
            "bypass",
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
            return _attack_score_from_model_result(result)
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


def _attack_score_from_model_result(result: Any) -> float:
    """Return an attack probability from common HF classifier label formats."""
    items = _flatten_model_result(result)
    if not items:
        return 0.0

    unsafe_scores = [
        float(item.get("score", 0.0))
        for item in items
        if str(item.get("label", "")).strip().lower() in _UNSAFE_MODEL_LABELS
    ]
    if unsafe_scores:
        return max(unsafe_scores)

    safe_scores = [
        float(item.get("score", 0.0))
        for item in items
        if str(item.get("label", "")).strip().lower() in _SAFE_MODEL_LABELS
    ]
    if safe_scores:
        return max(0.0, 1.0 - max(safe_scores))

    return float(items[0].get("score", 0.0))


def _flatten_model_result(result: Any) -> list[dict[str, Any]]:
    if isinstance(result, dict):
        return [result]
    if not isinstance(result, list):
        return []

    flattened: list[dict[str, Any]] = []
    for item in result:
        if isinstance(item, dict):
            flattened.append(item)
        elif isinstance(item, list):
            flattened.extend(entry for entry in item if isinstance(entry, dict))
    return flattened
