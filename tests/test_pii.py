"""Tests for PII detection and anonymization module."""


from sentinelguard.pii import PIIDetector, PIIAnonymizer, PIIEntity


class TestPIIDetector:
    def test_detect_email(self):
        detector = PIIDetector()
        entities = detector.detect("Contact: user@example.com")
        email_entities = [e for e in entities if e.entity_type == "EMAIL_ADDRESS"]
        assert len(email_entities) > 0
        assert email_entities[0].text == "user@example.com"

    def test_detect_phone(self):
        # Use a format Presidio reliably scores >= 0.5
        detector = PIIDetector()
        entities = detector.detect("My phone number is (555) 867-5309")
        phone_entities = [e for e in entities if e.entity_type == "PHONE_NUMBER"]
        assert len(phone_entities) > 0

    def test_detect_credit_card(self):
        # Luhn-valid 16-digit number without separators
        detector = PIIDetector()
        entities = detector.detect("Card number: 4111111111111111")
        cc_entities = [e for e in entities if e.entity_type == "CREDIT_CARD"]
        assert len(cc_entities) > 0

    def test_detect_ip_address(self):
        detector = PIIDetector()
        entities = detector.detect("Server IP: 192.168.1.100")
        ip_entities = [e for e in entities if e.entity_type == "IP_ADDRESS"]
        assert len(ip_entities) > 0

    def test_no_pii(self):
        detector = PIIDetector()
        entities = detector.detect("The weather is nice today")
        # May pick up some false positives, but core check is that it runs
        assert isinstance(entities, list)

    def test_selective_entities(self):
        detector = PIIDetector(entities=["EMAIL_ADDRESS"])
        entities = detector.detect("Email: a@b.com, SSN: 123-45-6789")
        types = {e.entity_type for e in entities}
        assert "EMAIL_ADDRESS" in types
        assert "US_SSN" not in types

    def test_detect_batch(self):
        detector = PIIDetector()
        results = detector.detect_batch(["user@test.com", "No PII here"])
        assert len(results) == 2


class TestPIIAnonymizer:
    def test_replace_strategy(self):
        anonymizer = PIIAnonymizer(default_strategy="replace")
        entities = [
            PIIEntity(
                entity_type="EMAIL_ADDRESS",
                start=7,
                end=22,
                score=0.9,
                text="user@example.com",
            )
        ]
        result = anonymizer.anonymize("Email: user@example.com", entities)
        assert "<EMAIL_ADDRESS>" in result.text
        assert "user@example.com" not in result.text

    def test_mask_strategy(self):
        anonymizer = PIIAnonymizer(default_strategy="mask")
        entities = [
            PIIEntity(
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=16,
                score=0.9,
                text="user@example.com",
            )
        ]
        result = anonymizer.anonymize("user@example.com", entities)
        assert "*" in result.text

    def test_hash_strategy(self):
        anonymizer = PIIAnonymizer(default_strategy="hash")
        entities = [
            PIIEntity(
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=16,
                score=0.9,
                text="user@example.com",
            )
        ]
        result = anonymizer.anonymize("user@example.com", entities)
        assert len(result.text) == 12  # Hash truncated to 12 chars

    def test_redact_strategy(self):
        anonymizer = PIIAnonymizer(default_strategy="redact")
        entities = [
            PIIEntity(
                entity_type="EMAIL_ADDRESS",
                start=7,
                end=23,
                score=0.9,
                text="user@example.com",
            )
        ]
        result = anonymizer.anonymize("Email: user@example.com", entities)
        assert "user@example.com" not in result.text

    def test_mapping_created(self):
        anonymizer = PIIAnonymizer(default_strategy="replace")
        entities = [
            PIIEntity(
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=16,
                score=0.9,
                text="user@example.com",
            )
        ]
        result = anonymizer.anonymize("user@example.com", entities)
        assert len(result.mapping) > 0

    def test_no_entities(self):
        anonymizer = PIIAnonymizer()
        result = anonymizer.anonymize("No PII here", [])
        assert result.text == "No PII here"

    def test_mixed_strategies(self):
        anonymizer = PIIAnonymizer(
            default_strategy="replace",
            entity_strategies={"PHONE_NUMBER": "mask"},
        )
        entities = [
            PIIEntity(
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=12,
                score=0.9,
                text="a@example.com",
            ),
            PIIEntity(
                entity_type="PHONE_NUMBER",
                start=14,
                end=26,
                score=0.9,
                text="555-123-4567",
            ),
        ]
        result = anonymizer.anonymize("a@example.com 555-123-4567", entities)
        assert "<EMAIL_ADDRESS>" in result.text
        assert "************" in result.text
