"""PII detection and anonymization examples for SentinelGuard."""

from sentinelguard.pii import PIIDetector, PIIAnonymizer


def example_basic_detection():
    """Basic PII detection."""
    detector = PIIDetector(
        language="en",
        score_threshold=0.5,
    )

    text = (
        "Please contact John Smith at john.smith@example.com or "
        "call 555-123-4567. His SSN is 123-45-6789 and credit card "
        "number is 4532-1234-5678-9012."
    )

    entities = detector.detect(text)

    print("Detected PII entities:")
    for entity in entities:
        print(
            f"  Type: {entity.entity_type}, "
            f"Text: '{entity.text}', "
            f"Score: {entity.score:.2f}"
        )


def example_anonymization():
    """PII anonymization with different strategies."""
    detector = PIIDetector()
    anonymizer = PIIAnonymizer(default_strategy="replace")

    text = "Email me at alice@example.com or call 555-987-6543"
    entities = detector.detect(text)

    # Replace strategy
    result = anonymizer.anonymize(text, entities)
    print(f"Replace: {result.text}")

    # Mask strategy
    mask_anonymizer = PIIAnonymizer(default_strategy="mask")
    result = mask_anonymizer.anonymize(text, entities)
    print(f"Mask:    {result.text}")

    # Hash strategy
    hash_anonymizer = PIIAnonymizer(default_strategy="hash")
    result = hash_anonymizer.anonymize(text, entities)
    print(f"Hash:    {result.text}")

    # Redact strategy
    redact_anonymizer = PIIAnonymizer(default_strategy="redact")
    result = redact_anonymizer.anonymize(text, entities)
    print(f"Redact:  {result.text}")


def example_selective_entities():
    """Detect only specific entity types."""
    detector = PIIDetector(
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER"],
        score_threshold=0.5,
    )

    text = (
        "Contact: bob@example.com, 555-111-2222, SSN: 111-22-3333"
    )

    entities = detector.detect(text)
    print("Selective detection (email + phone only):")
    for entity in entities:
        print(f"  {entity.entity_type}: {entity.text}")


def example_mixed_strategies():
    """Use different anonymization strategies per entity type."""
    detector = PIIDetector()
    anonymizer = PIIAnonymizer(
        default_strategy="replace",
        entity_strategies={
            "EMAIL_ADDRESS": "mask",
            "CREDIT_CARD": "hash",
        },
    )

    text = "Email: user@test.com, Card: 4111-1111-1111-1111, Phone: 555-000-1234"
    entities = detector.detect(text)
    result = anonymizer.anonymize(text, entities)

    print(f"Mixed strategies: {result.text}")
    print(f"Mapping: {result.mapping}")


if __name__ == "__main__":
    print("=== Basic Detection ===")
    example_basic_detection()
    print("\n=== Anonymization ===")
    example_anonymization()
    print("\n=== Selective Entities ===")
    example_selective_entities()
    print("\n=== Mixed Strategies ===")
    example_mixed_strategies()
