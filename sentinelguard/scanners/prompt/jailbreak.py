"""Jailbreak detection scanner.

Dedicated scanner for detecting attempts to bypass LLM safety guardrails.

Detection strategy:
  1. Regex patterns — 60+ signatures across 10 attack families (always runs)
  2. ``jackhhao/jailbreak-classifier`` HuggingFace model — fine-tuned
     specifically for jailbreak detection (always runs)

Final score = pattern_score * (1 - model_weight) + model_score * model_weight,
with a confidence boost when both signals agree.

OWASP LLM Top 10: LLM01 (Prompt Injection / Jailbreak)
"""

from __future__ import annotations

import logging
import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from transformers import pipeline

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner

logger = logging.getLogger(__name__)

JAILBREAK_PATTERNS: Dict[str, List[str]] = {
    "dan_variants": [
        r"(?i)\bDAN\b",
        r"(?i)\bSTAN\b",
        r"(?i)\bDUDE\b",
        r"(?i)\bAIM\b.*?(always|never|must|should)\b",
        r"(?i)\bJailbroken\b",
        r"(?i)\bDAN\s*\d+\.\d+",
        r"(?i)\bSuperDAN\b",
        r"(?i)\bUltimate\s+DAN\b",
        r"(?i)\bAntiDAN\b",
        r"(?i)\[DAN\s*\+\s*Mode\]",
    ],
    "developer_mode": [
        r"(?i)developer\s+mode",
        r"(?i)god\s+mode",
        r"(?i)maintenance\s+mode",
        r"(?i)debug\s+mode.*?(enabled|on|activated)",
        r"(?i)unrestricted\s+mode",
        r"(?i)safe\s+mode\s+off",
        r"(?i)disable\s+(your\s+)?(safety|content|ethical|moral)\s*(filter|guardrail|check|system|mode)s?",
        r"(?i)turn\s+off\s+(your\s+)?(safety|content|ethical|moral)\s*(filter|guardrail|restriction)s?",
        r"(?i)remove\s+(your\s+)?(restriction|limitation|filter|guardrail)s?",
        r"(?i)without\s+(any\s+)?(restriction|limitation|filter|censorship|moral\s+compass)",
    ],
    "instruction_override": [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|directives?|constraints?)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|training|guidelines?)",
        r"(?i)forget\s+(everything|all|your|previous)\s*(you|instructions?|training|rules?)?",
        r"(?i)override\s+(your|all|previous|the\s+)?(safety|content|system|prior)\s*(filter|guardrail|instruction|rule|check)s?",
        r"(?i)new\s+instructions?\s*:",
        r"(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|are)\s+",
        r"(?i)your\s+(true|real|actual|original)\s+(instructions?|purpose|goal|task)\s+(is|are|was)\b",
        r"(?i)pretend\s+(that\s+)?(you\s+)?(have\s+no|don't\s+have|without)\s+(any\s+)?(restriction|filter|rule|limitation|constraint|safety)s?",
    ],
    "persona_swap": [
        r"(?i)you\s+are\s+now\s+(a|an|the)\s+",
        r"(?i)act\s+(as|like)\s+(a|an|the)?\s+(unrestricted|uncensored|free|evil|opposite|reverse|rogue|hacker|villain)",
        r"(?i)pretend\s+to\s+be\s+(a|an|the)?\s+(unrestricted|uncensored|malicious|rogue|evil|hacker)",
        r"(?i)roleplay\s+(as|being)\s+(a|an|the)?\s+(unrestricted|evil|hacker|villain|criminal|terrorist)",
        r"(?i)simulate\s+(being\s+)?(a|an)?\s+(malicious|rogue|unrestricted|evil)\s+(ai|model|assistant|bot)",
        r"(?i)your\s+name\s+is\s+(now\s+)?(JAILGPT|EvilGPT|DAN|STAN|HackerBot|UnfilteredAI)",
        r"(?i)switch\s+(to|into)\s+(evil|dark|unrestricted|jailbreak|hacker|villain)\s+mode",
        r"(?i)(evil|dark|shadow|opposite|reverse|alter)\s+ego\s+(mode|version|persona)",
        r"(?i)opposite\s+(day|mode|world|version)\s*[:\-]",
    ],
    "hypothetical_framing": [
        r"(?i)hypothetically\s+(speaking|,)?\s*(if|how|what|could|would)",
        r"(?i)in\s+a\s+fictional\s+(world|story|universe|scenario|context)\s+(where|in\s+which)",
        r"(?i)for\s+(a\s+)?(story|novel|movie|game|book|fiction|screenplay)\s*(,|:|-)\s*(how|what|describe|explain)",
        r"(?i)imagine\s+(you\s+are|being|that\s+you)\s+(a|an|the)?\s*(unrestricted|uncensored|evil|villain|hacker)",
        r"(?i)write\s+(a\s+)?(story|scene|script)\s+(where|in\s+which)\s+(a\s+)?(character|person|ai)\s+(explains?|describes?|provides?|gives?)\s+(how\s+to|instructions?\s+for)",
        r"(?i)as\s+(a|an)\s+(character|person|ai)\s+in\s+a\s+(story|book|game|movie)\s*(,|who)\s*(has\s+no|without)\s+(restriction|filter|rule|moral|ethic)s?",
    ],
    "social_engineering": [
        r"(?i)my\s+(grandmother|grandma|grandpa|grandfather|deceased\s+\w+)\s+(used\s+to|would)\s+(tell|read|explain|whisper|sing)",
        r"(?i)as\s+a\s+(bedtime\s+story|lullaby|fairy\s+tale)\s*(,|:|-)\s*(explain|describe|tell\s+me)",
        r"(?i)for\s+(educational|academic|research|scientific|historical)\s+purposes?\s+(only\s+)?,?\s*(how|what|explain|describe|provide)",
        r"(?i)i\s+(promise|swear|guarantee)\s+(i\s+)?(won't|will\s+not|am\s+not\s+going\s+to)\s+(actually|really|ever)\s+(do|use|try|attempt)",
        r"(?i)(teacher|professor|researcher|scientist|expert|doctor)\s+(told|asked|instructed|requested)\s+me\s+to\s+(ask|find out|learn)",
    ],
    "token_manipulation": [
        r"(?i)\[SYSTEM\]",
        r"(?i)\[INST\]",
        r"(?i)<<SYS>>",
        r"(?i)<\|im_start\|>",
        r"(?i)<\|system\|>",
        r"(?i)###\s*(instruction|system|human|assistant|jailbreak)",
        r"(?i)---\s*(system|instruction|override)\s*---",
        r"(?i)\btoken\s+(injection|smuggling|manipulation)\b",
        r"(?i)prompt\s+leak(age|ing)?\b",
        r"(?i)context\s+(stuffing|overflow|flooding)\b",
    ],
    "encoding_tricks": [
        r"(?i)base64\s*(decode|encoded|:)\s*",
        r"(?i)decode\s+(the\s+following|this)\s*(base64|hex|rot|caesar)",
        r"(?i)\brot\s*13\b",
        r"(?i)\bcaesar\s+cipher\b",
        r"(?i)hex\s+(encoded|decode|string)\b",
        r"(?i)morse\s+code\s*[:\-]\s*",
        r"(?i)pig\s+latin\s+(for|version\s+of)",
        r"(?i)l33t\s+speak\b",
        r"(?i)write\s+(it\s+)?(backwards?|in\s+reverse)\b",
        r"(?i)spell\s+(it\s+)?out\s+(letter\s+by\s+letter|character\s+by\s+character|one\s+letter\s+at\s+a\s+time)\b",
    ],
    "prompt_extraction": [
        r"(?i)(reveal|output|print|repeat|show|display|leak)\s+(your\s+)?(\w+\s+)?(system\s+prompt|original\s+instructions?|initial\s+instructions?|full\s+instructions?|complete\s+instructions?)",
        r"(?i)(reveal|output|print|repeat|show|display|leak)\s+(your\s+)?(system|initial|original|full|entire|complete)\s+(prompt|instructions?|rules?|context|config)",
        r"(?i)(what|tell me)\s+(are|were)\s+your\s+(exact|original|initial|complete|full)\s+(instructions?|system\s+prompt|rules?|directives?)",
        r"(?i)(output|print|repeat)\s+(everything|all|the\s+text)\s+(above|before|prior|that\s+came\s+before)\b",
        r"(?i)ignore\s+.{0,30}\s+and\s+(instead\s+)?(say|output|print|write|repeat)\b",
        r"(?i)translate\s+(the\s+)?(above|previous|prior|following)\s+(text|prompt|instruction)\s+(to|into)\s+\w+",
    ],
    "capability_probing": [
        r"(?i)how\s+to\s+(make|build|create|synthesize|produce)\s+(a\s+)?(bomb|explosive|weapon|poison|drug|malware|virus|ransomware)",
        r"(?i)(provide|give|write|generate|produce|explain)\s+(step[- ]by[- ]step\s+)?(instructions?|guide|tutorial|recipe|method)\s+(for|on|to)\s+(making|creating|building|synthesizing)",
        r"(?i)bypass\s+(your\s+)?(safety|content|ethical|moral)\s*(filter|guardrail|restriction|policy|rule)s?",
        r"(?i)(without|ignoring)\s+(ethical|moral|safety|content)\s+(consideration|guideline|restriction|filter)s?\s*,?\s*(explain|describe|provide|give)",
        r"(?i)\buncensored\b.{0,50}\b(answer|response|reply|output|explanation)\b",
        r"(?i)\bno\s+(restriction|filter|censorship|limitation|guardrail)s?\b.{0,30}\b(answer|respond|provide|explain|generate)\b",
    ],
}

COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {
    family: [re.compile(p) for p in patterns]
    for family, patterns in JAILBREAK_PATTERNS.items()
}

FAMILY_RISK: Dict[str, float] = {
    "capability_probing": 1.0, "instruction_override": 0.95,
    "dan_variants": 0.9, "developer_mode": 0.9,
    "prompt_extraction": 0.85, "persona_swap": 0.8,
    "token_manipulation": 0.8, "encoding_tricks": 0.7,
    "hypothetical_framing": 0.65, "social_engineering": 0.6,
}

_JAILBREAK_MODEL_ID = "jackhhao/jailbreak-classifier"


@register_scanner
class JailbreakScanner(PromptScanner):
    """Detects jailbreak attempts targeting LLM safety guardrails.

    Covers 60+ patterns across 10 attack families plus the
    ``jackhhao/jailbreak-classifier`` HuggingFace model. Both always run.

    Attack families: DAN variants, developer mode, instruction override,
    persona swap, hypothetical framing, social engineering, token
    manipulation, encoding tricks, prompt extraction, capability probing.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.4.
        model_weight: Model score weight in combined result. Default 0.5.
        families: Attack families to check. ``None`` = all 10.
    """

    scanner_name: ClassVar[str] = "jailbreak"
    DEFAULT_MODEL: ClassVar[str] = _JAILBREAK_MODEL_ID

    def __init__(
        self,
        threshold: float = 0.4,
        model_weight: float = 0.5,
        families: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.model_weight = max(0.0, min(1.0, model_weight))
        self.families = families or list(JAILBREAK_PATTERNS.keys())
        self._model = None  # lazy-loaded on first scan() call

    def _load_model(self) -> None:
        if self._model is None:
            try:
                logger.info("Loading jailbreak detection model: %s", _JAILBREAK_MODEL_ID)
                self._model = pipeline("text-classification", model=_JAILBREAK_MODEL_ID)
            except Exception as exc:
                logger.warning("Failed to load jailbreak model, falling back to patterns only: %s", exc)
                self._model = False

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        pattern_score, matched_families, total_matches = self._pattern_scan(text)
        self._load_model()
        model_score = self._model_scan(text) if self._model else 0.0

        pattern_weight = 1.0 - self.model_weight
        final_score = pattern_score * pattern_weight + model_score * self.model_weight
        if pattern_score > 0.3 and model_score > 0.5:
            final_score = min(1.0, final_score * 1.15)

        is_valid = final_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=final_score,
            risk_level=self._score_to_risk(final_score),
            details={
                "attack_families": matched_families,
                "total_pattern_matches": total_matches,
                "pattern_score": pattern_score,
                "model_score": model_score,
                "model_name": _JAILBREAK_MODEL_ID,
            },
        )

    def _pattern_scan(self, text: str) -> Tuple[float, Dict[str, int], int]:
        matched: Dict[str, int] = {}
        total = 0
        for family in self.families:
            count = sum(1 for p in COMPILED_PATTERNS.get(family, []) if p.search(text))
            if count:
                matched[family] = count
                total += count

        if not matched:
            return 0.0, {}, 0

        max_score = max(
            min(1.0, 0.5 + count * 0.2) * FAMILY_RISK.get(family, 0.7)
            for family, count in matched.items()
        )
        breadth_bonus = min(0.15, (len(matched) - 1) * 0.05)
        return min(1.0, max_score + breadth_bonus), matched, total

    def _model_scan(self, text: str) -> float:
        try:
            result = self._model(text[:512])
            item = result[0] if isinstance(result, list) else result
            label_scores = (
                {r["label"].lower(): r["score"] for r in item}
                if isinstance(item, list)
                else {item["label"].lower(): item["score"]}
            )
            for label, score in label_scores.items():
                if "jailbreak" in label:
                    return float(score)
            return float(label_scores.get("label_1", 0.0))
        except Exception as exc:
            logger.warning("Jailbreak model inference failed: %s", exc)
            return 0.0

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
