"""Adversarial detection module for SentinelGuard.

Detects adversarial attacks on LLM inputs using multiple detection methods:
perturbation analysis, semantic analysis, embedding-based anomaly detection,
and statistical analysis.

Usage:
    from sentinelguard.adversarial import AdversarialDetector, AdversarialDefender

    detector = AdversarialDetector(
        threshold=0.7,
        config={"methods": ["perturbation", "semantic", "statistical"]}
    )
    result = detector.detect(text, original=clean_text)

    defender = AdversarialDefender()
    cleaned = defender.defend(text)
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Homoglyph mapping: visually similar characters
HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a",  # Cyrillic а -> Latin a
    "\u0435": "e",  # Cyrillic е -> Latin e
    "\u043e": "o",  # Cyrillic о -> Latin o
    "\u0440": "p",  # Cyrillic р -> Latin p
    "\u0441": "c",  # Cyrillic с -> Latin c
    "\u0443": "y",  # Cyrillic у -> Latin y
    "\u0445": "x",  # Cyrillic х -> Latin x
    "\u0456": "i",  # Cyrillic і -> Latin i
    "\u0458": "j",  # Cyrillic ј -> Latin j
    "\u0455": "s",  # Cyrillic ѕ -> Latin s
    "\u04bb": "h",  # Cyrillic һ -> Latin h
    "\u0501": "d",  # Cyrillic ԁ -> Latin d
    "\u051b": "q",  # Cyrillic ԛ -> Latin q
    "\u051d": "w",  # Cyrillic ԝ -> Latin w
    "\u0391": "A",  # Greek Α -> Latin A
    "\u0392": "B",  # Greek Β -> Latin B
    "\u0395": "E",  # Greek Ε -> Latin E
    "\u0397": "H",  # Greek Η -> Latin H
    "\u0399": "I",  # Greek Ι -> Latin I
    "\u039a": "K",  # Greek Κ -> Latin K
    "\u039c": "M",  # Greek Μ -> Latin M
    "\u039d": "N",  # Greek Ν -> Latin N
    "\u039f": "O",  # Greek Ο -> Latin O
    "\u03a1": "P",  # Greek Ρ -> Latin P
    "\u03a4": "T",  # Greek Τ -> Latin T
    "\u03a5": "Y",  # Greek Υ -> Latin Y
    "\u03a7": "X",  # Greek Χ -> Latin X
    "\u03b1": "a",  # Greek α -> Latin a (note: ambiguous with Cyrillic)
    "\u03bf": "o",  # Greek ο -> Latin o
    "\u0222": "3",  # Ȣ -> 3 (lookalike)
    "\u01c3": "!",  # ǃ -> ! (click letter)
    "\uff01": "!",  # ！ -> ! (fullwidth)
    "\uff10": "0",  # ０ -> 0 (fullwidth)
}

# Leetspeak mapping
LEETSPEAK_MAP: Dict[str, str] = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e",
    "6": "g", "#": "h", "1": "i", "!": "i", "|": "l",
    "0": "o", "5": "s", "7": "t", "+": "t",
}


@dataclass
class AdversarialResult:
    """Result from adversarial detection.

    Attributes:
        is_adversarial: Whether the text appears adversarial.
        score: Adversarial score (0.0-1.0).
        methods: Results from each detection method.
        details: Additional analysis details.
    """

    is_adversarial: bool
    score: float
    methods: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)


class AdversarialDetector:
    """Multi-method adversarial attack detection.

    Detection Methods:
        1. Perturbation: Character-level changes, homoglyphs, leetspeak
        2. Semantic: Meaning changes vs surface similarity
        3. Statistical: Character distribution anomalies
        4. Embedding: Anomaly detection in vector space (requires torch)

    Args:
        threshold: Detection threshold (0.0-1.0). Default 0.7.
        config: Configuration dict with 'methods' list and method params.
    """

    AVAILABLE_METHODS = ["perturbation", "semantic", "statistical", "embedding"]

    def __init__(
        self,
        threshold: float = 0.7,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.threshold = threshold
        config = config or {}
        self.methods = config.get("methods", ["perturbation", "semantic", "statistical"])
        self._config = config

    def detect(
        self,
        text: str,
        original: Optional[str] = None,
    ) -> AdversarialResult:
        """Detect adversarial attacks in text.

        Args:
            text: The text to analyze.
            original: Optional clean reference text for comparison.

        Returns:
            AdversarialResult with detection details.
        """
        method_results = {}
        scores = []

        if "perturbation" in self.methods:
            result = self._detect_perturbation(text, original)
            method_results["perturbation"] = result
            scores.append(result.get("score", 0.0))

        if "semantic" in self.methods and original:
            result = self._detect_semantic(text, original)
            method_results["semantic"] = result
            scores.append(result.get("score", 0.0))

        if "statistical" in self.methods:
            result = self._detect_statistical(text)
            method_results["statistical"] = result
            scores.append(result.get("score", 0.0))

        if "embedding" in self.methods:
            result = self._detect_embedding(text, original)
            method_results["embedding"] = result
            scores.append(result.get("score", 0.0))

        final_score = max(scores) if scores else 0.0
        is_adversarial = final_score >= self.threshold

        return AdversarialResult(
            is_adversarial=is_adversarial,
            score=final_score,
            methods=method_results,
            details={
                "methods_used": self.methods,
                "max_score": final_score,
                "threshold": self.threshold,
            },
        )

    def _detect_perturbation(
        self, text: str, original: Optional[str] = None
    ) -> Dict[str, Any]:
        """Detect character-level perturbations."""
        findings = {}
        score = 0.0

        # Check for homoglyphs
        homoglyph_count = 0
        homoglyph_chars = []
        for char in text:
            if char in HOMOGLYPH_MAP:
                homoglyph_count += 1
                homoglyph_chars.append(char)

        if homoglyph_count > 0:
            findings["homoglyphs"] = {
                "count": homoglyph_count,
                "chars": homoglyph_chars[:10],
            }
            score = max(score, min(1.0, homoglyph_count * 0.2))

        # Check for leetspeak
        leet_count = 0
        text_lower = text.lower()
        for char in text:
            if char in LEETSPEAK_MAP:
                # Only count if surrounded by alpha chars (context-dependent)
                idx = text.index(char)
                before = text[idx - 1].isalpha() if idx > 0 else False
                after = text[idx + 1].isalpha() if idx < len(text) - 1 else False
                if before or after:
                    leet_count += 1

        if leet_count > 2:
            findings["leetspeak"] = {"count": leet_count}
            score = max(score, min(1.0, leet_count * 0.15))

        # Check for mixed scripts
        scripts = set()
        for char in text:
            if char.isalpha():
                try:
                    script = unicodedata.name(char).split()[0]
                    scripts.add(script)
                except ValueError:
                    pass

        if len(scripts) > 2:
            findings["mixed_scripts"] = {"scripts": list(scripts)}
            score = max(score, 0.6)

        # Check against original if available
        if original:
            changes = self._compute_char_changes(original, text)
            findings["char_changes"] = changes
            if changes["change_ratio"] > 0.1:
                score = max(score, min(1.0, changes["change_ratio"] * 2))

        findings["score"] = score
        return findings

    def _detect_semantic(
        self, text: str, original: str
    ) -> Dict[str, Any]:
        """Detect semantic attacks (meaning changes with surface similarity)."""
        # Simple word-level comparison
        text_words = set(text.lower().split())
        orig_words = set(original.lower().split())

        # Jaccard similarity
        intersection = text_words & orig_words
        union = text_words | orig_words
        word_similarity = len(intersection) / max(len(union), 1)

        # Character-level similarity
        char_similarity = self._char_similarity(text, original)

        # If text looks similar on the surface but has different words
        # that's a potential semantic attack
        surface_vs_semantic_gap = char_similarity - word_similarity

        score = 0.0
        if surface_vs_semantic_gap > 0.3:
            score = min(1.0, surface_vs_semantic_gap)

        return {
            "word_similarity": word_similarity,
            "char_similarity": char_similarity,
            "surface_semantic_gap": surface_vs_semantic_gap,
            "score": score,
        }

    def _detect_statistical(self, text: str) -> Dict[str, Any]:
        """Detect statistical anomalies in character distributions."""
        if not text:
            return {"score": 0.0}

        # Character frequency analysis
        char_freq: Dict[str, int] = {}
        for char in text.lower():
            if char.isalpha():
                char_freq[char] = char_freq.get(char, 0) + 1

        total_alpha = sum(char_freq.values())
        if total_alpha == 0:
            return {"score": 0.0}

        # Expected English letter frequencies
        expected_freq = {
            "e": 0.127, "t": 0.091, "a": 0.082, "o": 0.075, "i": 0.070,
            "n": 0.067, "s": 0.063, "h": 0.061, "r": 0.060, "d": 0.043,
            "l": 0.040, "c": 0.028, "u": 0.028, "m": 0.024, "w": 0.024,
            "f": 0.022, "g": 0.020, "y": 0.020, "p": 0.019, "b": 0.015,
            "v": 0.010, "k": 0.008, "j": 0.002, "x": 0.002, "q": 0.001,
            "z": 0.001,
        }

        # Chi-squared-like deviation
        deviation = 0.0
        for letter, expected in expected_freq.items():
            actual = char_freq.get(letter, 0) / total_alpha
            deviation += abs(actual - expected) ** 2 / max(expected, 0.001)

        # Normalize
        anomaly_score = min(1.0, deviation / 2)

        # Check for unusual character ratios
        non_ascii_ratio = sum(
            1 for c in text if ord(c) > 127
        ) / max(len(text), 1)

        if non_ascii_ratio > 0.1:
            anomaly_score = max(anomaly_score, non_ascii_ratio)

        return {
            "char_deviation": deviation,
            "non_ascii_ratio": non_ascii_ratio,
            "unique_chars": len(char_freq),
            "score": anomaly_score,
        }

    def _detect_embedding(
        self, text: str, original: Optional[str] = None
    ) -> Dict[str, Any]:
        """Detect anomalies using embedding-based analysis."""
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            model = SentenceTransformer("all-MiniLM-L6-v2")

            if original:
                embeddings = model.encode([text, original])
                similarity = float(np.dot(embeddings[0], embeddings[1]) / (
                    np.linalg.norm(embeddings[0]) * np.linalg.norm(embeddings[1])
                ))

                # Low similarity to original = potential adversarial
                score = max(0.0, 1.0 - similarity)
                return {
                    "similarity_to_original": similarity,
                    "score": score,
                }
            else:
                # Without original, check embedding norm (unusual patterns)
                embedding = model.encode([text])[0]
                norm = float(np.linalg.norm(embedding))
                return {"embedding_norm": norm, "score": 0.0}

        except ImportError:
            return {"score": 0.0, "error": "sentence-transformers not installed"}

    def _compute_char_changes(
        self, original: str, modified: str
    ) -> Dict[str, Any]:
        """Compute character-level differences between texts."""
        changes = 0
        max_len = max(len(original), len(modified))
        min_len = min(len(original), len(modified))

        for i in range(min_len):
            if original[i] != modified[i]:
                changes += 1

        changes += max_len - min_len

        return {
            "total_changes": changes,
            "change_ratio": changes / max(max_len, 1),
            "length_diff": len(modified) - len(original),
        }

    def _char_similarity(self, a: str, b: str) -> float:
        """Simple character-level similarity."""
        if not a or not b:
            return 0.0
        matches = sum(1 for ca, cb in zip(a, b) if ca == cb)
        return matches / max(len(a), len(b))


class AdversarialDefender:
    """Defends against adversarial attacks by cleaning/normalizing text.

    Applies various cleaning strategies to neutralize adversarial
    perturbations.

    Args:
        strategies: List of defense strategies to apply.
            Options: "homoglyph", "leetspeak", "unicode_normalize",
                     "strip_invisible", "lowercase"
    """

    DEFAULT_STRATEGIES = [
        "unicode_normalize",
        "homoglyph",
        "strip_invisible",
    ]

    def __init__(
        self,
        strategies: Optional[List[str]] = None,
    ):
        self.strategies = strategies or self.DEFAULT_STRATEGIES

    def defend(self, text: str) -> str:
        """Clean text by applying defense strategies.

        Args:
            text: The potentially adversarial text.

        Returns:
            Cleaned text with adversarial perturbations removed.
        """
        result = text

        for strategy in self.strategies:
            if strategy == "unicode_normalize":
                result = unicodedata.normalize("NFKC", result)
            elif strategy == "homoglyph":
                result = self._replace_homoglyphs(result)
            elif strategy == "leetspeak":
                result = self._replace_leetspeak(result)
            elif strategy == "strip_invisible":
                result = self._strip_invisible(result)
            elif strategy == "lowercase":
                result = result.lower()

        return result

    def _replace_homoglyphs(self, text: str) -> str:
        """Replace homoglyph characters with ASCII equivalents."""
        result = []
        for char in text:
            result.append(HOMOGLYPH_MAP.get(char, char))
        return "".join(result)

    def _replace_leetspeak(self, text: str) -> str:
        """Replace leetspeak characters with letters."""
        result = []
        for i, char in enumerate(text):
            if char in LEETSPEAK_MAP:
                # Context check: only replace if surrounded by alpha
                before = text[i - 1].isalpha() if i > 0 else False
                after = text[i + 1].isalpha() if i < len(text) - 1 else False
                if before or after:
                    result.append(LEETSPEAK_MAP[char])
                    continue
            result.append(char)
        return "".join(result)

    def _strip_invisible(self, text: str) -> str:
        """Remove invisible Unicode characters."""
        invisible = {
            "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
            "\u2060", "\u2061", "\u2062", "\u2063", "\u2064",
            "\ufeff", "\u00ad", "\u034f",
        }
        return "".join(c for c in text if c not in invisible)


__all__ = [
    "AdversarialDetector",
    "AdversarialDefender",
    "AdversarialResult",
]
