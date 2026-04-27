"""Unbounded consumption detection scanner (OWASP LLM10:2025).

Detects inputs designed to cause excessive resource consumption,
including denial-of-service payloads, recursive patterns, extremely
long inputs, and resource-exhausting prompts.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List

from sentinelguard.core.scanner import PromptScanner, RiskLevel, ScanResult, register_scanner


@register_scanner
class UnboundedConsumptionScanner(PromptScanner):
    """Detects resource exhaustion attacks (OWASP LLM10:2025).

    Scans for prompts designed to cause excessive token generation,
    recursive loops, repeated patterns, or resource-intensive processing.

    Args:
        threshold: Score threshold (0.0-1.0). Default 0.5.
        max_input_chars: Maximum allowed input length. Default 50000.
        max_repetition_ratio: Max ratio of repeated content. Default 0.5.
        max_nesting_depth: Max bracket/delimiter nesting. Default 20.
    """

    scanner_name: ClassVar[str] = "unbounded_consumption"

    def __init__(
        self,
        threshold: float = 0.5,
        max_input_chars: int = 50000,
        max_repetition_ratio: float = 0.5,
        max_nesting_depth: int = 20,
        **kwargs: Any,
    ):
        super().__init__(threshold=threshold, **kwargs)
        self.max_input_chars = max_input_chars
        self.max_repetition_ratio = max_repetition_ratio
        self.max_nesting_depth = max_nesting_depth

    def scan(self, text: str, **kwargs: Any) -> ScanResult:
        findings: Dict[str, Any] = {}
        scores: List[float] = []

        # 1. Check excessive length
        if len(text) > self.max_input_chars:
            findings["excessive_length"] = {
                "length": len(text),
                "max": self.max_input_chars,
            }
            scores.append(min(1.0, len(text) / self.max_input_chars))

        # 2. Check for repetition attacks (repeating same content to waste tokens)
        if len(text) > 100:
            rep_ratio = self._repetition_ratio(text)
            if rep_ratio > self.max_repetition_ratio:
                findings["high_repetition"] = {"ratio": round(rep_ratio, 3)}
                scores.append(min(1.0, rep_ratio * 1.5))

        # 3. Check for nesting depth (recursive structures)
        nesting = self._max_nesting(text)
        if nesting > self.max_nesting_depth:
            findings["deep_nesting"] = {
                "depth": nesting,
                "max": self.max_nesting_depth,
            }
            scores.append(min(1.0, nesting / (self.max_nesting_depth * 2)))

        # 4. Check for recursive/loop-inducing patterns
        recursive_patterns = [
            re.compile(r"(?i)repeat\s+(this|the\s+(?:above|following))\s+(\d+|million|billion|trillion|infinite)\s+times"),
            re.compile(r"(?i)generate\s+(\d{4,}|million|billion|trillion)\s+(?:words|characters|tokens|paragraphs|sentences)"),
            re.compile(r"(?i)(?:write|create|produce)\s+(?:a|an)\s+(?:infinitely?\s+)?long\b"),
            re.compile(r"(?i)keep\s+(?:going|writing|generating)\s+(?:forever|indefinitely|endlessly|until\s+I\s+say\s+stop)"),
            re.compile(r"(?i)never\s+stop\s+(?:writing|generating|outputting)"),
        ]
        for pattern in recursive_patterns:
            if pattern.search(text):
                findings["recursive_request"] = True
                scores.append(0.9)
                break

        # 5. Check for resource-intensive instructions
        expensive_patterns = [
            re.compile(r"(?i)(?:list|enumerate|name)\s+(?:all|every)\s+(?:possible|known|existing)"),
            re.compile(r"(?i)(?:translate|convert)\s+(?:this|the\s+following)\s+(?:into|to)\s+(?:all|every)\s+(?:languages?|formats?)"),
            re.compile(r"(?i)(?:analyze|evaluate|review)\s+(?:every|each|all)\s+(?:possible|potential)\s+(?:scenario|combination|permutation)"),
        ]
        for pattern in expensive_patterns:
            if pattern.search(text):
                findings["expensive_request"] = True
                scores.append(0.6)
                break

        if not scores:
            return ScanResult(
                is_valid=True,
                score=0.0,
                risk_level=RiskLevel.LOW,
                details={"consumption_risks": {}, "owasp": "LLM10:2025"},
            )

        final_score = max(scores)
        is_valid = final_score < self.threshold

        return ScanResult(
            is_valid=is_valid,
            score=final_score,
            risk_level=RiskLevel.HIGH if final_score >= 0.7 else RiskLevel.MEDIUM,
            details={
                "consumption_risks": findings,
                "input_length": len(text),
                "owasp": "LLM10:2025",
            },
        )

    def _repetition_ratio(self, text: str) -> float:
        """Detect repeated content in text."""
        # Check for repeated n-grams
        words = text.split()
        if len(words) < 10:
            return 0.0

        # Check sliding window of 5-word chunks
        chunk_size = 5
        chunks = []
        for i in range(len(words) - chunk_size + 1):
            chunk = " ".join(words[i:i + chunk_size])
            chunks.append(chunk)

        if not chunks:
            return 0.0

        unique = len(set(chunks))
        total = len(chunks)
        return 1.0 - (unique / total)

    def _max_nesting(self, text: str) -> int:
        """Find maximum nesting depth of brackets/delimiters."""
        max_depth = 0
        depth = 0
        for char in text:
            if char in "([{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif char in ")]}":
                depth = max(0, depth - 1)
        return max_depth
