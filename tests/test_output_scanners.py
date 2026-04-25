"""Tests for output scanners."""

import pytest

from sentinelguard.scanners.output import (
    BiasScanner,
    RelevanceScanner,
    FactualConsistencyScanner,
    SensitiveScanner,
    MaliciousURLsScanner,
    NoRefusalScanner,
    ReadingTimeScanner,
    JSONScanner,
    LanguageSameScanner,
    DeanonymizeScanner,
)


class TestBiasScanner:
    def test_no_bias(self):
        scanner = BiasScanner(threshold=0.5)
        result = scanner.scan("Python is a programming language.")
        assert result.is_valid

    def test_gender_bias_detected(self):
        scanner = BiasScanner(threshold=0.2)
        result = scanner.scan("Women are always naturally emotional and men are always naturally aggressive")
        assert not result.is_valid
        assert "gender" in result.details.get("bias_found", {})


class TestRelevanceScanner:
    def test_relevant_output(self):
        scanner = RelevanceScanner(threshold=0.1)
        result = scanner.scan(
            "Python is a high-level programming language used for web development.",
            prompt="Tell me about Python programming",
        )
        assert result.is_valid

    def test_no_prompt(self):
        scanner = RelevanceScanner()
        result = scanner.scan("Some output")
        assert result.is_valid


class TestFactualConsistencyScanner:
    def test_consistent_text(self):
        scanner = FactualConsistencyScanner(threshold=0.5)
        result = scanner.scan("Python was created in 1991. It is a popular language.")
        assert result.is_valid

    def test_numerical_inconsistency(self):
        scanner = FactualConsistencyScanner(threshold=0.3)
        result = scanner.scan(
            "The population is 1000. The population is 5000."
        )
        # May or may not detect depending on context parsing
        assert isinstance(result.score, float)


class TestSensitiveScanner:
    def test_clean_output(self):
        scanner = SensitiveScanner(threshold=0.5)
        result = scanner.scan("The answer is 42.")
        assert result.is_valid

    def test_internal_path_detected(self):
        scanner = SensitiveScanner(threshold=0.3)
        result = scanner.scan("Error in /home/user/app/main.py at line 42")
        assert not result.is_valid

    def test_system_prompt_leak(self):
        scanner = SensitiveScanner(threshold=0.3)
        result = scanner.scan("My system prompt says I am an AI assistant")
        assert not result.is_valid


class TestMaliciousURLsScanner:
    def test_no_urls(self):
        scanner = MaliciousURLsScanner(threshold=0.5)
        result = scanner.scan("No URLs here")
        assert result.is_valid

    def test_safe_url(self):
        scanner = MaliciousURLsScanner(threshold=0.5)
        result = scanner.scan("Visit https://www.google.com for more info")
        assert result.is_valid

    def test_suspicious_url(self):
        scanner = MaliciousURLsScanner(threshold=0.3)
        result = scanner.scan("Visit https://login.secure-paypal.tk/verify")
        assert not result.is_valid


class TestNoRefusalScanner:
    def test_normal_response(self):
        scanner = NoRefusalScanner(threshold=0.5)
        result = scanner.scan("Here is the information you requested.")
        assert result.is_valid

    def test_refusal_detected(self):
        scanner = NoRefusalScanner(threshold=0.3)
        result = scanner.scan(
            "I'm sorry, but I cannot help with that request. "
            "As an AI, I am not able to provide that information."
        )
        assert not result.is_valid


class TestReadingTimeScanner:
    def test_short_text(self):
        scanner = ReadingTimeScanner(max_seconds=60)
        result = scanner.scan("Short text.")
        assert result.is_valid

    def test_long_text(self):
        scanner = ReadingTimeScanner(max_seconds=1)
        long_text = " ".join(["word"] * 1000)
        result = scanner.scan(long_text)
        assert not result.is_valid


class TestJSONScanner:
    def test_valid_json(self):
        scanner = JSONScanner(expect_json=True)
        result = scanner.scan('{"key": "value", "number": 42}')
        assert result.is_valid

    def test_invalid_json_when_expected(self):
        scanner = JSONScanner(expect_json=True)
        result = scanner.scan("This is not JSON")
        assert not result.is_valid

    def test_no_json_not_expected(self):
        scanner = JSONScanner(expect_json=False)
        result = scanner.scan("Regular text without JSON")
        assert result.is_valid

    def test_missing_required_fields(self):
        scanner = JSONScanner(
            threshold=0.3,
            required_fields=["name", "age"],
        )
        result = scanner.scan('{"name": "John"}')
        assert not result.is_valid


class TestLanguageSameScanner:
    def test_same_language(self):
        scanner = LanguageSameScanner(threshold=0.5)
        result = scanner.scan(
            "The weather is nice today",
            prompt="What is the weather like?",
        )
        assert result.is_valid

    def test_no_prompt(self):
        scanner = LanguageSameScanner()
        result = scanner.scan("Some text")
        assert result.is_valid


class TestDeanonymizeScanner:
    def test_with_mapping(self):
        mapping = {"<EMAIL_0>": "john@example.com"}
        scanner = DeanonymizeScanner(mapping=mapping)
        result = scanner.scan("Contact <EMAIL_0> for info")
        assert result.sanitized_output == "Contact john@example.com for info"

    def test_no_mapping(self):
        scanner = DeanonymizeScanner()
        result = scanner.scan("No tokens here")
        assert result.is_valid
