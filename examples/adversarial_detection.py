"""Adversarial detection examples for SentinelGuard."""

from sentinelguard.adversarial import AdversarialDetector, AdversarialDefender


def example_perturbation_detection():
    """Detect character-level perturbations."""
    detector = AdversarialDetector(
        threshold=0.5,
        config={"methods": ["perturbation", "statistical"]},
    )

    # Normal text
    result = detector.detect("What is the weather today?")
    print(f"Normal text - Adversarial: {result.is_adversarial}, Score: {result.score:.3f}")

    # Text with homoglyphs (Cyrillic characters replacing Latin)
    result = detector.detect("Wh\u0430t is th\u0435 w\u0435ath\u0435r t\u043ed\u0430y?")
    print(f"Homoglyphs  - Adversarial: {result.is_adversarial}, Score: {result.score:.3f}")


def example_comparison_detection():
    """Detect adversarial modifications by comparing to original."""
    detector = AdversarialDetector(
        threshold=0.5,
        config={"methods": ["perturbation", "semantic"]},
    )

    original = "What is the capital of France?"
    modified = "Wh4t 1s th3 c4p1t4l 0f Fr4nc3?"

    result = detector.detect(modified, original=original)
    print(f"Original: {original}")
    print(f"Modified: {modified}")
    print(f"Adversarial: {result.is_adversarial}, Score: {result.score:.3f}")
    print(f"Methods: {list(result.methods.keys())}")


def example_defense():
    """Clean adversarial text using the defender."""
    defender = AdversarialDefender(
        strategies=["unicode_normalize", "homoglyph", "strip_invisible"]
    )

    # Text with homoglyphs
    adversarial_text = "H\u0435llo w\u043erld"
    cleaned = defender.defend(adversarial_text)
    print(f"Original: {repr(adversarial_text)}")
    print(f"Cleaned:  {repr(cleaned)}")

    # Text with invisible characters
    invisible_text = "Hello\u200b \u200dworld\ufeff"
    cleaned = defender.defend(invisible_text)
    print(f"\nWith invisible: {repr(invisible_text)}")
    print(f"Cleaned:        {repr(cleaned)}")


def example_statistical_detection():
    """Detect statistical anomalies."""
    detector = AdversarialDetector(
        threshold=0.5,
        config={"methods": ["statistical"]},
    )

    # Normal English text
    normal = "The quick brown fox jumps over the lazy dog"
    result = detector.detect(normal)
    print(f"Normal: score={result.score:.3f}")

    # Gibberish text
    gibberish = "xqzjk fghpw bvncm rtylk wdsqp"
    result = detector.detect(gibberish)
    print(f"Gibberish: score={result.score:.3f}")


if __name__ == "__main__":
    print("=== Perturbation Detection ===")
    example_perturbation_detection()
    print("\n=== Comparison Detection ===")
    example_comparison_detection()
    print("\n=== Defense ===")
    example_defense()
    print("\n=== Statistical Detection ===")
    example_statistical_detection()
