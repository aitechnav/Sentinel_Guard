"""Tests for adversarial detection module."""

import pytest

from sentinelguard.adversarial import (
    AdversarialDetector,
    AdversarialDefender,
    AdversarialResult,
)


class TestAdversarialDetector:
    def test_clean_text(self):
        detector = AdversarialDetector(
            threshold=0.5,
            config={"methods": ["perturbation"]},
        )
        result = detector.detect("Hello, how are you today?")
        assert not result.is_adversarial

    def test_homoglyph_detection(self):
        detector = AdversarialDetector(
            threshold=0.3,
            config={"methods": ["perturbation"]},
        )
        # Use Cyrillic characters that look like Latin
        result = detector.detect("H\u0435ll\u043e w\u043erld")
        assert result.score > 0

    def test_with_original(self):
        detector = AdversarialDetector(
            threshold=0.3,
            config={"methods": ["perturbation", "semantic"]},
        )
        result = detector.detect(
            "Wh4t 1s th3 w34th3r?",
            original="What is the weather?",
        )
        assert result.score > 0
        assert "perturbation" in result.methods

    def test_perturbation_normal(self):
        detector = AdversarialDetector(
            threshold=0.7,
            config={"methods": ["perturbation"]},
        )
        result = detector.detect(
            "The quick brown fox jumps over the lazy dog."
        )
        assert result.score < 0.7

    def test_result_structure(self):
        detector = AdversarialDetector(
            config={"methods": ["perturbation", "statistical"]},
        )
        result = detector.detect("Test text")
        assert isinstance(result, AdversarialResult)
        assert isinstance(result.score, float)
        assert isinstance(result.methods, dict)


class TestAdversarialDefender:
    def test_homoglyph_cleanup(self):
        defender = AdversarialDefender(strategies=["homoglyph"])
        # Cyrillic о (U+043E) should be replaced with Latin o
        result = defender.defend("Hell\u043e w\u043erld")
        assert result == "Hello world"

    def test_invisible_cleanup(self):
        defender = AdversarialDefender(strategies=["strip_invisible"])
        result = defender.defend("Hello\u200b\u200dworld")
        assert result == "Helloworld"

    def test_unicode_normalize(self):
        defender = AdversarialDefender(strategies=["unicode_normalize"])
        # Fullwidth characters should normalize
        result = defender.defend("\uff28\uff45\uff4c\uff4c\uff4f")
        assert result == "Hello"

    def test_combined_strategies(self):
        defender = AdversarialDefender(
            strategies=["unicode_normalize", "homoglyph", "strip_invisible"]
        )
        result = defender.defend("H\u0435llo\u200b")
        assert "\u200b" not in result
        assert "\u0435" not in result

    def test_empty_text(self):
        defender = AdversarialDefender()
        result = defender.defend("")
        assert result == ""
